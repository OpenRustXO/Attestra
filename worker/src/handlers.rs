//! Request dispatch.

mod android;
mod challenge;
mod ios;
mod proxy;

use worker::{Env, Request, Response};

use crate::config::{AndroidConfig, AppleConfig, Config};
use crate::error::ApiError;
use crate::routes::{self, Route};

pub async fn handle(mut req: Request, env: &Env) -> Result<Response, ApiError> {
    let path = req.path();
    let route = routes::resolve(req.method().as_ref(), &path)?;
    let config = load_config(env)?;

    match route {
        Route::Challenge => challenge::issue(env, &config).await,
        Route::AttestIos => ios::attest(&mut req, env, &config, apple(&config)?).await,
        Route::AssertIos => ios::assert(&mut req, env, &config, apple(&config)?).await,
        Route::AttestAndroid => android::attest(&mut req, env, &config, android(&config)?).await,
        Route::Proxy { provider, path } => {
            proxy::handle(&mut req, env, &config, provider, path).await
        }
    }
}

fn load_config(env: &Env) -> Result<Config, ApiError> {
    Config::from_lookup(|name| env.var(name).ok().map(|v| v.to_string()))
        .map_err(|e| ApiError::Internal(format!("configuration: {e}")))
}

fn apple(config: &Config) -> Result<&AppleConfig, ApiError> {
    config
        .apple
        .as_ref()
        .ok_or(ApiError::NotImplemented("iOS is not configured"))
}

fn android(config: &Config) -> Result<&AndroidConfig, ApiError> {
    config
        .android
        .as_ref()
        .ok_or(ApiError::NotImplemented("Android is not configured"))
}
