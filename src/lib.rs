// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The reposnake contributors

pub mod auth;
pub mod config;
pub mod embed;
pub mod error;
pub mod idmouse;
pub mod kubernetes;
pub mod metadata;
pub mod object_store;
pub mod oci;
pub mod package;
pub mod repository;
#[cfg(feature = "s3")]
pub mod s3_object_store;
pub mod service;
pub mod web;
