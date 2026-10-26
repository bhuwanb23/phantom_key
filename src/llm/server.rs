//! HTTP Server for Phantom Key v2
//!
//! Provides REST API for:
//! - Processing prompts
//! - Storing/retrieving secrets
//! - Viewing ledger
//! - Running Attack Lab

use std::sync::Arc;
use tokio::sync::Mutex;
use warp::{Filter, Reply};
use serde_json::{json, Value};

use crate::llm::phantom_key::{PhantomKey, PhantomKeyError};
use crate::llm::attack_lab::AttackLab;
use crate::vault::storage::SecretType;

/// Create the HTTP router
pub fn create_router(
    phantom_key: Arc<Mutex<PhantomKey>>,
) -> impl Filter<Extract = impl Reply, Error = warp::Rejection> + Clone {
    // GET /health
    let health_route = warp::path!("health")
        .and(warp::get())
        .and_then(health_handler);

    // POST /process
    let process_route = warp::path!("process")
        .and(warp::post())
        .and(warp::body::json())
        .and(with_phantom_key(phantom_key.clone()))
        .and_then(process_handler);

    // POST /store-secret
    let store_route = warp::path!("store-secret")
        .and(warp::post())
        .and(warp::body::json())
        .and(with_phantom_key(phantom_key.clone()))
        .and_then(store_secret_handler);

    // GET /get-secret/{handle}
    let get_secret_route = warp::path!("get-secret" / String)
        .and(warp::get())
        .and(with_phantom_key(phantom_key.clone()))
        .and_then(get_secret_handler);

    // GET /ledger
    let ledger_route = warp::path!("ledger")
        .and(warp::get())
        .and(with_phantom_key(phantom_key.clone()))
        .and_then(ledger_handler);

    // GET /vault
    let vault_route = warp::path!("vault")
        .and(warp::get())
        .and(with_phantom_key(phantom_key.clone()))
        .and_then(vault_handler);

    // GET /attack-lab
    let attack_lab_route = warp::path!("attack-lab")
        .and(warp::get())
        .and(with_phantom_key(phantom_key.clone()))
        .and_then(attack_lab_handler);

    // GET /status
    let status_route = warp::path!("status")
        .and(warp::get())
        .and(with_phantom_key(phantom_key.clone()))
        .and_then(status_handler);

    // Combine all routes
    health_route
        .or(process_route)
        .or(store_route)
        .or(get_secret_route)
        .or(ledger_route)
        .or(vault_route)
        .or(attack_lab_route)
        .or(status_route)
        .recover(handle_error)
}

/// Handler for health check
async fn health_handler() -> Result<impl Reply, warp::Rejection> {
    Ok(warp::reply::json(&json!({
        "status": "ok",
        "version": "2.0",
        "name": "Phantom Key v2"
    })))
}

/// Handler for processing prompts
async fn process_handler(
    body: Value,
    phantom_key: Arc<Mutex<PhantomKey>>,
) -> Result<impl Reply, warp::Rejection> {
    let prompt = body["prompt"]
        .as_str()
        .ok_or_else(|| warp::reject::custom(ApiError::new("Missing 'prompt' field")))?;
    
    let model = body["model"]
        .as_str()
        .ok_or_else(|| warp::reject::custom(ApiError::new("Missing 'model' field")))?;
    
    let provider = body["provider"]
        .as_str()
        .map(|s| match s {
            "bedrock" => crate::llm::provider::ProviderType::Bedrock,
            "openai" => crate::llm::provider::ProviderType::OpenAI,
            "gemini" => crate::llm::provider::ProviderType::Gemini,
            _ => crate::llm::provider::ProviderType::Bedrock,
        })
        .unwrap_or(crate::llm::provider::ProviderType::Bedrock);

    let mut pk = phantom_key.lock().await;
    
    match pk.process_prompt(prompt, model, provider).await {
        Ok(response) => Ok(warp::reply::json(&json!({
            "response": response,
            "model": model,
            "provider": format!("{:?}", provider)
        }))),
        Err(e) => Err(warp::reject::custom(ApiError::from(e))),
    }
}

/// Handler for storing secrets
async fn store_secret_handler(
    body: Value,
    phantom_key: Arc<Mutex<PhantomKey>>,
) -> Result<impl Reply, warp::Rejection> {
    let secret = body["secret"]
        .as_str()
        .ok_or_else(|| warp::reject::custom(ApiError::new("Missing 'secret' field")))?;
    
    let secret_type = body["secret_type"]
        .as_str()
        .map(|s| match s.to_lowercase().as_str() {
            "aws_access_key" => SecretType::AwsAccessKey,
            "aws_secret_key" => SecretType::AwsSecretKey,
            "iban" => SecretType::IbAN,
            "credit_card" => SecretType::CreditCard,
            "api_key" => SecretType::ApiKey,
            "password" => SecretType::Password,
            _ => SecretType::Generic,
        })
        .unwrap_or(SecretType::Generic);

    let mut pk = phantom_key.lock().await;
    
    match pk.store_secret(secret.as_bytes(), secret_type).await {
        Ok(handle) => Ok(warp::reply::json(&json!({
            "handle": handle,
            "secret_type": format!("{:?}", secret_type)
        }))),
        Err(e) => Err(warp::reject::custom(ApiError::from(e))),
    }
}

/// Handler for getting secrets
async fn get_secret_handler(
    handle: String,
    phantom_key: Arc<Mutex<PhantomKey>>,
) -> Result<impl Reply, warp::Rejection> {
    let mut pk = phantom_key.lock().await;
    
    match pk.get_secret(&handle).await {
        Ok(secret) => Ok(warp::reply::json(&json!({
            "handle": handle,
            "secret": String::from_utf8_lossy(&secret)
        }))),
        Err(e) => Err(warp::reject::custom(ApiError::from(e))),
    }
}

/// Handler for getting ledger
async fn ledger_handler(
    phantom_key: Arc<Mutex<PhantomKey>>,
) -> Result<impl Reply, warp::Rejection> {
    let pk = phantom_key.lock().await;
    
    let entries: Vec<Value> = pk.get_ledger_entries()
        .into_iter()
        .map(|e| json!({
            "id": e.entry.id,
            "timestamp": e.entry.timestamp.to_rfc3339(),
            "request_id": e.entry.request_id,
            "provider": e.entry.provider,
            "method": e.entry.method,
            "url": e.entry.url,
            "payload_size": e.entry.payload.len()
        }))
        .collect();

    Ok(warp::reply::json(&json!({
        "entries": entries,
        "count": entries.len(),
        "chain_status": format!("{:?}", pk.ledger_status())
    })))
}

/// Handler for getting vault entries
async fn vault_handler(
    phantom_key: Arc<Mutex<PhantomKey>>,
) -> Result<impl Reply, warp::Rejection> {
    let pk = phantom_key.lock().await;
    
    let entries: Vec<Value> = pk.get_vault_entries()
        .into_iter()
        .map(|e| json!({
            "id": e.id,
            "handle": e.handle,
            "secret_type": format!("{:?}", e.metadata.secret_type),
            "created_at": e.metadata.created_at.to_rfc3339(),
            "access_count": e.metadata.access_count
        }))
        .collect();

    Ok(warp::reply::json(&json!({
        "entries": entries,
        "count": entries.len()
    })))
}

/// Handler for running Attack Lab
async fn attack_lab_handler(
    phantom_key: Arc<Mutex<PhantomKey>>,
) -> Result<impl Reply, warp::Rejection> {
    let pk = phantom_key.lock().await;
    let attack_lab = AttackLab::new(pk.clone());
    
    let results = attack_lab.run_all_demos().await;
    
    let demo_names = [
        "Memory Safety",
        "Log Inspection",
        "Wire Inspection",
        "DLEQ Validation",
        "Ledger Tampering",
        "Canary Detection",
    ];
    
    let results_json: Vec<Value> = results.iter()
        .enumerate()
        .map(|(i, &result)| json!({
            "demo": demo_names[i],
            "passed": result
        }))
        .collect();

    let pass_count = results.iter().filter(|&&r| r).count();

    Ok(warp::reply::json(&json!({
        "results": results_json,
        "passed": pass_count,
        "total": results.len(),
        "all_passed": pass_count == results.len()
    })))
}

/// Handler for getting status
async fn status_handler(
    phantom_key: Arc<Mutex<PhantomKey>>,
) -> Result<impl Reply, warp::Rejection> {
    let pk = phantom_key.lock().await;
    
    Ok(warp::reply::json(&json!({
        "current_epoch": pk.current_epoch(),
        "ledger_status": format!("{:?}", pk.ledger_status()),
        "ledger_entries": pk.get_ledger_entries().len(),
        "vault_entries": pk.get_vault_entries().len(),
        "providers": pk.providers.len()
    })))
}

/// Create a filter that provides PhantomKey
fn with_phantom_key(
    phantom_key: Arc<Mutex<PhantomKey>>,
) -> impl Filter<Extract = (Arc<Mutex<PhantomKey>>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || phantom_key.clone())
}

/// API error type
#[derive(Debug)]
pub struct ApiError {
    message: String,
    status_code: u16,
}

impl ApiError {
    pub fn new(message: &str) -> Self {
        Self {
            message: message.to_string(),
            status_code: 400,
        }
    }
}

impl From<PhantomKeyError> for ApiError {
    fn from(error: PhantomKeyError) -> Self {
        Self {
            message: error.to_string(),
            status_code: 500,
        }
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ApiError {}

/// Handle API errors
async fn handle_error(err: warp::Rejection) -> Result<impl Reply, std::convert::Infallible> {
    if let Some(api_error) = err.find() {
        Ok(warp::reply::with_status(
            warp::reply::json(&json!({
                "error": api_error.message
            })),
            warp::http::StatusCode::from_u16(api_error.status_code).unwrap_or(warp::http::StatusCode::INTERNAL_SERVER_ERROR),
        ))
    } else {
        Ok(warp::reply::with_status(
            warp::reply::json(&json!({
                "error": "Internal server error"
            })),
            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
        ))
    }
}
