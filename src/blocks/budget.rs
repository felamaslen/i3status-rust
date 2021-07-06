use std::collections::HashMap;
use std::env;
use std::time::Duration;

use crossbeam_channel::Sender;
use serde_derive::Deserialize;
use serde_json::Value;

use crate::blocks::{Block, ConfigBlock, Update};
use crate::config::SharedConfig;
use crate::errors::*;
use crate::scheduler::Task;
use crate::widgets::{text::TextWidget, I3BarWidget, State};

use reqwest::header::{HeaderMap, AUTHORIZATION};
use reqwest::Client;

const BUDGET_API_URL_ENV: &str = "BUDGET_API_URL";
const BUDGET_API_PIN_ENV: &str = "BUDGET_API_PIN";

pub struct Budget {
    id: usize,
    text: TextWidget,
    api_url: Option<String>,
    pin: Option<String>,
    update_interval: Duration,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct BudgetConfig {
    pub api_url: Option<String>,
    pub pin: Option<String>,
}

impl Default for BudgetConfig {
    fn default() -> Self {
        Self {
            api_url: env::var(BUDGET_API_URL_ENV).ok(),
            pin: env::var(BUDGET_API_PIN_ENV).ok(),
        }
    }
}

impl ConfigBlock for Budget {
    type Config = BudgetConfig;

    fn new(
        id: usize,
        block_config: Self::Config,
        shared_config: SharedConfig,
        _tx_update_request: Sender<Task>,
    ) -> Result<Self> {
        Ok(Budget {
            id,
            api_url: block_config.api_url,
            pin: block_config.pin,
            update_interval: Duration::from_secs(60),
            text: TextWidget::new(id, 0, shared_config).with_icon("budget")?,
        })
    }
}

fn get_url_graphql(api_url: &str) -> String {
    return format!("{api_url}/graphql", api_url = api_url,);
}

fn format_stock_value(latest_value: i64, previous_value: i64) -> (String, State) {
    let today_profit_loss: f64 = (latest_value - previous_value) as f64;
    let latest_value_float: f64 = latest_value as f64;

    let text = format!(
        "£{:.2} (£{:.2})",
        latest_value_float / 100.0,
        today_profit_loss / 100.0
    );

    let mut state = State::Good;

    if today_profit_loss < 0.0 {
        state = State::Warning;
    }

    (text, state)
}

impl Budget {
    async fn login(&mut self, client: &Client) -> Result<String> {
        let api_url = self.api_url.as_ref().unwrap();
        let url_graphql = get_url_graphql(api_url);

        let pin = self.pin.as_ref().unwrap();

        let mut body_login = HashMap::new();
        body_login.insert(
            "query",
            "mutation Login($pin: Int!) { login(pin: $pin) { error apiKey } }",
        );
        let variables = format!("{{\"pin\": {pin}}}", pin = pin,);
        body_login.insert("variables", &variables);

        match client.post(url_graphql).json(&body_login).send().await {
            Ok(res) => match res.json::<Value>().await {
                Ok(login_response) => {
                    let api_key = &login_response["data"]["login"]["apiKey"].as_str();
                    if api_key.is_none() {
                        self.text.set_state(State::Critical);
                        return Err(BlockError("Budget".to_owned(), "Invalid login".to_string()));
                    }

                    Ok(api_key.unwrap().to_string())
                }
                Err(e) => {
                    self.text.set_state(State::Critical);
                    Err(BlockError(
                        "Budget".to_owned(),
                        format!("Parse error: {}", e.to_string()),
                    ))
                }
            },
            Err(e) => {
                self.text.set_state(State::Critical);
                Err(BlockError(
                    "Budget".to_owned(),
                    format!("API Error: {}", e.to_string()),
                ))
            }
        }
    }

    async fn get_stock_value(&mut self, client: &Client, api_key: &str) -> Result<i64> {
        let api_url = self.api_url.as_ref().unwrap();
        let url_graphql = get_url_graphql(api_url);

        let mut body_query = HashMap::new();
        body_query.insert(
            "query",
            "
        query StockValue {
            stockValue {
                latestValue
                previousValue
            }
        }
        ",
        );

        let mut headers = HeaderMap::new();

        headers.insert(AUTHORIZATION, api_key.parse().unwrap());

        let response = client
            .post(url_graphql)
            .headers(headers)
            .json(&body_query)
            .send()
            .await;

        match response {
            Ok(res) => match res.json::<Value>().await {
                Ok(query_response) => {
                    let latest_value =
                        &query_response["data"]["stockValue"]["latestValue"].as_i64();
                    let previous_value =
                        &query_response["data"]["stockValue"]["previousValue"].as_i64();

                    if latest_value.is_none() || previous_value.is_none() {
                        self.text.set_text("-".to_owned());
                        self.text.set_state(State::Critical);
                        return Ok(0);
                    }

                    let (text, state) =
                        format_stock_value(latest_value.unwrap(), previous_value.unwrap());

                    self.text.set_text(text);
                    self.text.set_state(state);

                    Ok(latest_value.unwrap())
                }
                Err(e) => Err(BlockError("Budget".to_owned(), e.to_string())),
            },
            Err(e) => {
                self.text.set_state(State::Critical);
                Err(BlockError(
                    "Budget".to_owned(),
                    format!("Error fetching: {}", e.to_string()),
                ))
            }
        }
    }

    async fn make_request(&mut self) -> Result<()> {
        let client = Client::new();

        match self.login(&client).await {
            Ok(api_key) => {
                if let Err(e) = self.get_stock_value(&client, &api_key).await {
                    return Err(e);
                }
                Ok(())
            }
            Err(e) => Err(BlockError(
                "Budget".to_owned(),
                format!("Error logging in: {}", e.to_string()),
            )),
        }
    }
}

impl Block for Budget {
    fn update(&mut self) -> Result<Option<Update>> {
        if self.api_url.is_none() {
            return Err(BlockError("Budget".to_owned(), format!(
                    "Missing member 'api_url'. Add the member or configure with the environment variable {}",
                    BUDGET_API_URL_ENV.to_string())));
        }
        if self.pin.is_none() {
            return Err(BlockError("Budget".to_owned(), format!(
                    "Missing member 'pin'. Add the member or configure with the environment variable {}",
                    BUDGET_API_PIN_ENV.to_string())));
        }

        let rt = tokio::runtime::Runtime::new().unwrap();
        if let Err(e) = rt.block_on(self.make_request()) {
            return Err(e);
        }

        Ok(Some(self.update_interval.into()))
    }

    fn view(&self) -> Vec<&dyn I3BarWidget> {
        vec![&self.text]
    }

    fn id(&self) -> usize {
        self.id
    }
}
