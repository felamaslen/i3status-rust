use std::cmp;
use std::collections::HashMap;
use std::env;
use std::time::Duration;

use crossbeam_channel::Sender;
use num_format::{Locale, ToFormattedString};
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

pub struct FormatCurrencyOptions {
    abbreviate: bool,
    brackets: bool,
    custom_precision: Option<u32>,
    pence: bool,
    symbol: bool,
}

fn round(value: f64, precision: u32) -> f64 {
    let exp = 10_i64.pow(precision) as f64;
    return (value * exp).round() / exp;
}

fn currency_display_value(abs_value: f64, log: u32, pence: bool, precision: u32) -> f64 {
    if log > 0 {
        return round(abs_value / ((10_i64.pow(log * 3)) as f64), precision);
    }
    if !pence {
        return abs_value.round();
    }
    return abs_value;
}

fn round_currency_value(
    display_value: f64,
    formatted_int: String,
    precision: u32,
    log: u32,
    pence: bool,
) -> String {
    if log == 0 && !pence {
        return formatted_int;
    }
    let remainder = display_value - display_value.floor();
    return format!(
        "{}{}",
        formatted_int,
        &format!("{:.1$}", remainder, precision as usize)[1..]
    );
}

fn get_precision(abbreviate: bool, log: u32, custom_precision: Option<u32>) -> u32 {
    if abbreviate && log == 0 {
        return 2;
    }
    if let Some(precision) = custom_precision {
        return precision;
    }
    if abbreviate {
        return 0;
    }
    2
}

fn format_currency(value: i64, maybe_options: &Option<FormatCurrencyOptions>) -> String {
    let mut abbreviate: bool = false;
    let mut brackets: bool = false;
    let mut symbol: bool = true;
    let mut pence: bool = true;
    let mut custom_precision: Option<u32> = None;

    if let Some(options) = &maybe_options {
        abbreviate = options.abbreviate;
        brackets = options.brackets;
        symbol = options.symbol;
        pence = options.pence;
        custom_precision = options.custom_precision;
    }

    let mut sign: String = "".to_owned();
    if !brackets && value < 0 {
        sign = "\u{2212}".to_owned();
    }

    let mut symbol_output: String = "".to_owned();
    if symbol {
        symbol_output = "£".to_owned();
    }

    let abs_value: f64 = (value.abs() as f64) / 100.0;

    let abbreviations: [String; 4] = [
        "k".to_string(),
        "m".to_string(),
        "bn".to_string(),
        "tn".to_string(),
    ];

    let mut log: u32 = 0;
    if abbreviate && value != 0 {
        log = cmp::min((abs_value.log10() / 3.0).floor() as u32, 4);
    }

    let precision = get_precision(abbreviate, log, custom_precision);

    let mut abbreviation = "".to_owned();
    if log > 0 {
        abbreviation = abbreviations[(log as usize) - 1].to_owned();
    }

    let display_value = currency_display_value(abs_value, log, pence, precision);
    let display_int: i64 = display_value.floor() as i64;

    let formatted_int = display_int.to_formatted_string(&Locale::en);
    let formatted = round_currency_value(display_value, formatted_int, precision, log, pence);

    if brackets && value < 0 {
        return format!("({}{}{})", symbol_output, formatted, abbreviation);
    }

    return format!("{}{}{}{}", sign, symbol_output, formatted, abbreviation);
}

fn format_stock_value(latest_value: i64, previous_value: i64) -> (String, State) {
    let today_profit_loss: i64 = latest_value - previous_value;

    let text = format!(
        "{} ; {}",
        format_currency(
            latest_value,
            &Some(FormatCurrencyOptions {
                abbreviate: true,
                brackets: false,
                custom_precision: Some(1),
                pence: false,
                symbol: true,
            })
        ),
        format_currency(
            today_profit_loss,
            &Some(FormatCurrencyOptions {
                abbreviate: false,
                brackets: true,
                custom_precision: None,
                pence: true,
                symbol: true,
            })
        ),
    );

    let mut state = State::Good;

    if today_profit_loss < 0 {
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

#[cfg(test)]
mod tests {
    use crate::blocks::budget::{format_currency, FormatCurrencyOptions};

    #[test]
    fn test_format_currency_gbx_with_comma() {
        let format_options = None;

        assert_eq!(format_currency(1, &format_options), "£0.01");
        assert_eq!(format_currency(-1, &format_options), "\u{2212}£0.01");
        assert_eq!(format_currency(145, &format_options), "£1.45");
        assert_eq!(
            format_currency(1823123919, &format_options),
            "£18,231,239.19"
        );
    }

    #[test]
    fn test_format_currency_brackets() {
        let format_options = Some(FormatCurrencyOptions {
            abbreviate: false,
            brackets: true,
            custom_precision: None,
            pence: true,
            symbol: true,
        });

        assert_eq!(format_currency(-8123, &format_options), "(£81.23)");
        assert_eq!(format_currency(192, &format_options), "£1.92");
    }

    #[test]
    fn test_format_currency_symbol() {
        let format_options = Some(FormatCurrencyOptions {
            abbreviate: false,
            brackets: false,
            custom_precision: None,
            pence: true,
            symbol: false,
        });

        assert_eq!(format_currency(99123, &format_options), "991.23");
    }

    #[test]
    fn test_format_currency_pence() {
        let format_options = Some(FormatCurrencyOptions {
            abbreviate: false,
            brackets: false,
            custom_precision: None,
            pence: false,
            symbol: true,
        });

        assert_eq!(format_currency(17493, &format_options), "£175");
        assert_eq!(format_currency(17443, &format_options), "£174");
    }

    #[test]
    fn test_format_currency_abbreviate() {
        let format_options = Some(FormatCurrencyOptions {
            abbreviate: true,
            brackets: false,
            custom_precision: None,
            pence: true,
            symbol: true,
        });

        assert_eq!(format_currency(1000, &format_options), "£10.00");
        assert_eq!(format_currency(191233, &format_options), "£2k");
        assert_eq!(format_currency(128633219, &format_options), "£1m");
        assert_eq!(format_currency(7859128633219, &format_options), "£79bn");
        assert_eq!(format_currency(981123199100139, &format_options), "£10tn");
    }

    #[test]
    fn test_format_currency_abbreviate_precision() {
        let format_options = Some(FormatCurrencyOptions {
            abbreviate: true,
            brackets: false,
            custom_precision: Some(1),
            pence: true,
            symbol: true,
        });

        assert_eq!(format_currency(818231238, &format_options), "£8.2m");
    }
}
