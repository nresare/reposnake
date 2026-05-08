// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The reposnake contributors

use anyhow::{Context, anyhow};
use handlebars::{Handlebars, Template};
use rust_embed::Embed;
use serde::Serialize;
use std::sync::Arc;

#[derive(Clone)]
pub struct Templates {
    registry: Arc<Handlebars<'static>>,
}

impl Templates {
    pub fn new() -> Result<Self, anyhow::Error> {
        let mut registry = Handlebars::new();
        registry.register_template("index", WebTemplates::compile("index.html.tmpl")?);
        registry.register_template("project", WebTemplates::compile("project.html.tmpl")?);
        Ok(Self {
            registry: Arc::new(registry),
        })
    }

    pub fn render<T>(&self, name: &str, data: &T) -> Result<String, handlebars::RenderError>
    where
        T: Serialize,
    {
        self.registry.render(name, data)
    }
}

#[derive(Embed)]
#[folder = "web_templates"]
struct WebTemplates;

impl Compile for WebTemplates {}

pub trait Compile: Embed {
    fn compile(path: &'static str) -> Result<Template, anyhow::Error> {
        let embedded_file =
            Self::get(path).ok_or_else(|| anyhow!("could not find template '{path}'"))?;
        let template = std::str::from_utf8(embedded_file.data.as_ref())
            .context(format!("invalid utf-8 sequence in web_templates/{path}"))?;
        Ok(Template::compile(template)?)
    }
}
