use plist::{Date, Dictionary, Value};
use serde::Deserialize;

use crate::Error;

use super::{DeveloperSession, QHResponseMeta};
use crate::developer_endpoint;

impl DeveloperSession {
    pub async fn qh_list_devices(&self, team_id: &String) -> Result<DevicesResponse, Error> {
        let endpoint = developer_endpoint!("/QH65B2/ios/listDevices.action");

        let mut body = Dictionary::new();
        body.insert("teamId".to_string(), Value::String(team_id.clone()));

        let response = self.qh_send_request(&endpoint, Some(body)).await?;
        let response_data: DevicesResponse = plist::from_value(&Value::Dictionary(response))?;

        Ok(response_data)
    }

    pub async fn qh_add_device(
        &self,
        team_id: &String,
        device_name: &String,
        device_udid: &String,
        device_type: Option<DeviceType>,
    ) -> Result<DeviceResponse, Error> {
        let endpoint = developer_endpoint!("/QH65B2/ios/addDevice.action");

        let mut body = Dictionary::new();
        body.insert("teamId".to_string(), Value::String(team_id.clone()));
        body.insert("name".to_string(), Value::String(device_name.clone()));
        body.insert(
            "deviceNumber".to_string(),
            Value::String(device_udid.clone()),
        );
        if let Some(DeviceType::Tvos) = device_type {
            body.insert(
                "DTDK_Platform".to_string(),
                Value::String("tvos".to_string()),
            );
            body.insert("subPlatform".to_string(), Value::String("tvOS".to_string()));
        }

        let response = self.qh_send_request(&endpoint, Some(body)).await?;
        let response_data: DeviceResponse = plist::from_value(&Value::Dictionary(response))?;

        Ok(response_data)
    }

    pub async fn qh_get_device(
        &self,
        team_id: &String,
        device_udid: &String,
    ) -> Result<Option<Device>, Error> {
        let response_data = self.qh_list_devices(team_id).await?;

        let device = response_data
            .devices
            .into_iter()
            .find(|dev| dev.device_number == *device_udid);

        Ok(device)
    }

    pub async fn qh_ensure_device(
        &self,
        team_id: &String,
        device_name: &String,
        device_udid: &String,
        device_type: Option<DeviceType>,
    ) -> Result<Device, Error> {
        if let Some(device) = self.qh_get_device(team_id, device_udid).await? {
            Ok(device)
        } else {
            let response = self
                .qh_add_device(team_id, device_name, device_udid, device_type)
                .await?;
            Ok(response.device)
        }
    }
}

/// Which Apple platform a device/provisioning-profile request targets.
///
/// Vendored from `bitxeno/PlumeImpactor`'s fork of this crate, which added
/// this enum specifically to request tvOS (not iOS) device records and
/// provisioning profiles -- required for Apple TV, our only target. See
/// `qh_get_profile` for the matching provisioning-profile side of this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    Any,
    Ios,
    Tvos,
    Watchos,
    Visionos,
}

impl DeviceType {
    pub fn from_string(s: &str) -> Self {
        let s = s.to_lowercase();
        if s.contains("iphone") || s.contains("ipad") || s.contains("ios") {
            Self::Ios
        } else if s.contains("tvos") || s.contains("apple tv") || s.contains("appletv") {
            Self::Tvos
        } else if s.contains("watchos") || s.contains("watch") {
            Self::Watchos
        } else if s.contains("visionos") || s.contains("vision") {
            Self::Visionos
        } else {
            Self::Any
        }
    }
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DevicesResponse {
    pub devices: Vec<Device>,
    #[serde(flatten)]
    pub meta: QHResponseMeta,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DeviceResponse {
    pub device: Device,
    #[serde(flatten)]
    pub meta: QHResponseMeta,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Device {
    device_id: String,
    name: String,
    device_number: String,
    device_platform: String,
    status: String,
    device_class: String,
    expiration_date: Option<Date>,
}
