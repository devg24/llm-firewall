use std::path::Path;
use candle_core::Device;
use candle_transformers::models::bert::{BertModel, Config};
use tokenizers::Tokenizer;

pub struct SharedModel {
    pub model: BertModel,
    pub tokenizer: Tokenizer,
}

impl SharedModel {
    pub fn load_from_dir(model_dir: &Path) -> Result<Self, String> {
        let config_path = model_dir.join("config.json");
        let tokenizer_path = model_dir.join("tokenizer.json");
        let safetensors_path = model_dir.join("model.safetensors");

        // 1. Load Config
        let config_file = std::fs::File::open(&config_path)
            .map_err(|e| e.to_string())?;
        let config: Config = serde_json::from_reader(config_file)
            .map_err(|e| e.to_string())?;

        // 2. Load Tokenizer
        let tokenizer = Tokenizer::from_file(&tokenizer_path)
            .map_err(|e| e.to_string())?;

        // 3. Load Weights (VarBuilder)
        let device = Device::Cpu;
        let var_builder = match unsafe { candle_nn::VarBuilder::from_mmaped_safetensors(&[&safetensors_path], candle_core::DType::F32, &device) } {
            Ok(vb) => vb,
            Err(_) => {
                let data = std::fs::read(&safetensors_path).map_err(|e| e.to_string())?;
                candle_nn::VarBuilder::from_buffered_safetensors(data, candle_core::DType::F32, &device)
                    .map_err(|e| e.to_string())?
            }
        };

        // 4. Construct Model
        let model = BertModel::load(var_builder, &config)
            .map_err(|e| e.to_string())?;

        Ok(Self { model, tokenizer })
    }
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
}
