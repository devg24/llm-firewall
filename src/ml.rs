use std::path::Path;
use candle_core::Device;
use candle_transformers::models::bert::{BertModel, Config};
use tokenizers::Tokenizer;
use tokio::sync::Semaphore;
use crate::proxy::ProxyError;
use std::sync::Arc;
use candle_nn::Module;
pub struct SharedModel {
    pub model: BertModel,
    pub classifier: candle_nn::Linear,
    pub tokenizer: Tokenizer,
    pub id2label: std::collections::HashMap<usize, String>,
    pub inference_semaphore: Arc<Semaphore>,
    pub device: Device,
}

impl SharedModel {
    pub fn load_from_dir(model_dir: &Path) -> Result<Self, String> {
        let config_path = model_dir.join("config.json");
        let tokenizer_path = model_dir.join("tokenizer.json");
        let safetensors_path = model_dir.join("model.safetensors");

        // 1. Load Config
        let config_file = std::fs::File::open(&config_path)
            .map_err(|e| e.to_string())?;
        let config_json: serde_json::Value = serde_json::from_reader(config_file)
            .map_err(|e| e.to_string())?;
        
        let config: Config = serde_json::from_value(config_json.clone())
            .map_err(|e| e.to_string())?;

        let mut id2label = std::collections::HashMap::new();
        if let Some(map) = config_json.get("id2label").and_then(|v| v.as_object()) {
            for (k, v) in map {
                if let (Ok(idx), Some(label)) = (k.parse::<usize>(), v.as_str()) {
                    id2label.insert(idx, label.to_string());
                }
            }
        }
        if id2label.is_empty() {
            // Default BERT NER labels if not found
            let labels = ["O", "B-MISC", "I-MISC", "B-PERSON", "I-PERSON", "B-ORG", "I-ORG", "B-GPE", "I-GPE"];
            for (i, label) in labels.iter().enumerate() {
                id2label.insert(i, label.to_string());
            }
        }

        // 2. Load Tokenizer
        let tokenizer = Tokenizer::from_file(&tokenizer_path)
            .map_err(|e| e.to_string())?;

        // 3. Load Weights (VarBuilder)
        let device = Device::Cpu;
        let inference_semaphore = Arc::new(Semaphore::new(1));
        let var_builder = match unsafe { candle_nn::VarBuilder::from_mmaped_safetensors(&[&safetensors_path], candle_core::DType::F32, &device) } {
            Ok(vb) => vb,
            Err(_) => {
                let data = std::fs::read(&safetensors_path).map_err(|e| e.to_string())?;
                candle_nn::VarBuilder::from_buffered_safetensors(data, candle_core::DType::F32, &device)
                    .map_err(|e| e.to_string())?
            }
        };

        // 4. Construct Model
        let model = BertModel::load(var_builder.clone(), &config)
            .map_err(|e| e.to_string())?;

        let num_labels = id2label.len();
        let classifier_weight = var_builder.get((num_labels, config.hidden_size), "classifier.weight").map_err(|e| e.to_string())?;
        let classifier_bias = var_builder.get(num_labels, "classifier.bias").map_err(|e| e.to_string())?;
        let classifier = candle_nn::Linear::new(classifier_weight, Some(classifier_bias));

        Ok(Self { model, classifier, tokenizer, id2label, inference_semaphore, device })
    }
}



#[derive(Debug, Clone, PartialEq)]
pub struct TokenClassification {
    pub word: String,
    pub entity_group: String,
    pub score: f32,
    pub start: usize,
    pub end: usize,
}

#[tracing::instrument(skip(model, text))]
pub async fn run_inference(model: Arc<SharedModel>, text: String) -> Result<Vec<TokenClassification>, ProxyError> {
    if text.len() > 100_000 {
        return Err(ProxyError::Internal("Text too long".to_string()));
    }
    let permit = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        model.inference_semaphore.clone().acquire_owned()
    )
    .await
    .map_err(|_| ProxyError::TooManyRequests)?
    .map_err(|_| ProxyError::Internal("Semaphore closed".to_string()))?;
    
    let result = tokio::time::timeout(std::time::Duration::from_secs(120), tokio::task::spawn_blocking(move || {
        let _permit = permit;

        // Tokenize raw text without special tokens to get content tokens & offsets
        let encoding = model.tokenizer.encode(text.clone(), false)
            .map_err(|e| ProxyError::Internal(format!("Tokenization error: {}", e)))?;
        
        let raw_tokens = encoding.get_ids();
        let offsets = encoding.get_offsets();
        if raw_tokens.is_empty() {
            return Ok(vec![]);
        }

        let cls_id = model.tokenizer.token_to_id("[CLS]").unwrap_or(101);
        let sep_id = model.tokenizer.token_to_id("[SEP]").unwrap_or(102);

        // Max content tokens per chunk is 510 (leaving room for [CLS] and [SEP])
        let max_content_len = 510;
        let mut results = Vec::new();

        let stride = 256;
        let mut chunk_start = 0;
        while chunk_start < raw_tokens.len() {
            let chunk_end = std::cmp::min(chunk_start + max_content_len, raw_tokens.len());
            let chunk_raw_tokens = &raw_tokens[chunk_start..chunk_end];

            // Build sequence with [CLS] and [SEP]
            let mut sequence_tokens = Vec::with_capacity(chunk_raw_tokens.len() + 2);
            sequence_tokens.push(cls_id);
            sequence_tokens.extend_from_slice(chunk_raw_tokens);
            sequence_tokens.push(sep_id);

            let input_tensor = candle_core::Tensor::new(&sequence_tokens[..], &model.device)
                .map_err(|e| ProxyError::Internal(e.to_string()))?
                .unsqueeze(0) // Batch size 1
                .map_err(|e| ProxyError::Internal(e.to_string()))?;

            // Forward pass
            let token_type_ids = input_tensor.zeros_like().map_err(|e| ProxyError::Internal(e.to_string()))?;
            let embeddings = model.model.forward(&input_tensor, &token_type_ids, None)
                .map_err(|e| ProxyError::Internal(e.to_string()))?;

            // Apply classifier
            let logits = model.classifier.forward(&embeddings)
                .map_err(|e| ProxyError::Internal(e.to_string()))?;

            // Compute softmax probabilities
            let probabilities = candle_nn::ops::softmax(&logits, candle_core::D::Minus1)
                .map_err(|e| ProxyError::Internal(e.to_string()))?
                .squeeze(0)
                .map_err(|e| ProxyError::Internal(e.to_string()))?;
            let prob_vec = probabilities.to_vec2::<f32>().map_err(|e| ProxyError::Internal(e.to_string()))?;

            // Extract argmax predictions
            let predictions = logits.argmax(candle_core::D::Minus1)
                .map_err(|e| ProxyError::Internal(e.to_string()))?
                .squeeze(0)
                .map_err(|e| ProxyError::Internal(e.to_string()))?
                .to_vec1::<u32>()
                .map_err(|e| ProxyError::Internal(e.to_string()))?;

            // Content tokens correspond to indices 1..=chunk_raw_tokens.len()
            for (i, &pred) in predictions[1..=chunk_raw_tokens.len()].iter().enumerate() {
                let actual_token_idx = chunk_start + i;
                let label = model.id2label.get(&(pred as usize)).unwrap_or(&"O".to_string()).clone();
                if label != "O" {
                    let offset = offsets[actual_token_idx];
                    if offset.0 < offset.1 && offset != (0, 0) {
                        let mut s = offset.0;
                        let mut e = offset.1;
                        while s > 0 && !text.is_char_boundary(s) { s -= 1; }
                        while e <= text.len() && !text.is_char_boundary(e) { e += 1; }
                        if e > text.len() { e = text.len(); }
                        if let Some(word_slice) = text.get(s..e) {
                            let score_val = prob_vec.get(i + 1).and_then(|row| row.get(pred as usize)).copied().unwrap_or(1.0);

                            results.push(TokenClassification {
                                word: word_slice.to_string(),
                                entity_group: label,
                                score: score_val,
                                start: offset.0,
                                end: offset.1,
                            });
                        }
                    }
                }
            }
            if chunk_end == raw_tokens.len() { break; }
            chunk_start += stride;
        }
        
        results.sort_by_key(|r: &TokenClassification| r.start);
        results.dedup_by(|a, b| a.start == b.start && a.end == b.end && a.entity_group == b.entity_group);

        Ok(results)
    })).await.map_err(|_| ProxyError::Internal("Inference timeout".to_string()))?.map_err(|_| ProxyError::Internal("Inference task panicked".to_string()))??;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_load_from_non_existent_dir() {
        let dir = Path::new("/path/that/does/not/exist");
        let result = SharedModel::load_from_dir(dir);
        assert!(result.is_err());
    }



    #[tokio::test]
    async fn test_run_inference_with_model() {
        let dir = Path::new("model");
        if !dir.exists() {
            return;
        }
        let model = Arc::new(SharedModel::load_from_dir(dir).unwrap());
        
        let text = "My name is John Doe and I work at Google in New York.".to_string();
        let result = run_inference(model.clone(), text).await.unwrap();
        
        // Ensure some entities were found (John Doe, Google, New York)
        assert!(!result.is_empty());

        let has_per = result.iter().any(|r| r.entity_group.contains("PER"));
        let has_org = result.iter().any(|r| r.entity_group.contains("ORG"));
        let has_loc = result.iter().any(|r| r.entity_group.contains("LOC"));
        
        assert!(has_per, "Missing PER entity");
        assert!(has_org, "Missing ORG entity");
        assert!(has_loc, "Missing LOC entity");
        
        // Test chunking with long text
        let long_text = "Apple ".repeat(600); // 600 words, > 512 tokens
        let long_result = run_inference(model, long_text).await.unwrap();
        assert!(!long_result.is_empty());
    }
}


