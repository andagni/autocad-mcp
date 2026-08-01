use super::PortablePlotError;

/// A CAD entity property before layer and block inheritance is resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Property<T> {
    ByLayer,
    ByBlock,
    Explicit(T),
}

/// The concrete values available while resolving one entity property.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropertyContext<T> {
    layer: T,
    immediate_insert: Option<T>,
}

impl<T> PropertyContext<T> {
    /// Create a context from an already-resolved layer value and optional
    /// already-resolved immediate INSERT value.
    pub fn new(layer: T, immediate_insert: Option<T>) -> Self {
        Self {
            layer,
            immediate_insert,
        }
    }

    pub fn layer(&self) -> &T {
        &self.layer
    }

    pub fn immediate_insert(&self) -> Option<&T> {
        self.immediate_insert.as_ref()
    }
}

impl<T: Clone> Property<T> {
    /// Resolve exactly one cascade level.
    ///
    /// Nested inserts call this again with the outer insert's already-resolved
    /// value. A missing ByBlock context is never replaced with a guessed
    /// default.
    pub fn resolve(&self, context: &PropertyContext<T>) -> Result<T, PortablePlotError> {
        match self {
            Self::Explicit(value) => Ok(value.clone()),
            Self::ByLayer => Ok(context.layer.clone()),
            Self::ByBlock => context.immediate_insert.clone().ok_or_else(|| {
                PortablePlotError::new(
                    "by_block_context_missing",
                    "ByBlock property requires an already-resolved immediate INSERT value",
                )
            }),
        }
    }
}

/// The only valid ownership contexts for layer-zero inheritance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayerContext<'a> {
    Root,
    Insert { effective_layer: &'a str },
}

/// Resolve an entity's effective layer for one ownership level.
///
/// Layer `0` inherits only inside an INSERT. Other layer names remain
/// unchanged, including nested insert layers that have already been resolved.
pub fn effective_layer<'a>(
    entity_layer: &'a str,
    context: LayerContext<'a>,
) -> Result<&'a str, PortablePlotError> {
    if entity_layer.is_empty() {
        return Err(PortablePlotError::new(
            "invalid_layer_name",
            "entity layer name must not be empty",
        ));
    }
    match context {
        LayerContext::Insert { effective_layer } if entity_layer.eq_ignore_ascii_case("0") => {
            if effective_layer.is_empty() {
                return Err(PortablePlotError::new(
                    "invalid_layer_name",
                    "effective INSERT layer name must not be empty",
                ));
            }
            Ok(effective_layer)
        }
        LayerContext::Root | LayerContext::Insert { .. } => Ok(entity_layer),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_property_does_not_consult_context() {
        let context = PropertyContext::new("layer", None);
        assert_eq!(
            Property::Explicit("entity").resolve(&context).unwrap(),
            "entity"
        );
    }

    #[test]
    fn by_layer_uses_concrete_layer_value() {
        let context = PropertyContext::new("layer", Some("insert"));
        assert_eq!(Property::ByLayer.resolve(&context).unwrap(), "layer");
    }

    #[test]
    fn by_block_uses_immediate_insert_value() {
        let context = PropertyContext::new("layer", Some("insert"));
        assert_eq!(Property::ByBlock.resolve(&context).unwrap(), "insert");
    }

    #[test]
    fn by_block_without_insert_context_rejects() {
        let error = Property::<&str>::ByBlock
            .resolve(&PropertyContext::new("layer", None))
            .unwrap_err();
        assert_eq!(error.code(), "by_block_context_missing");
    }

    #[test]
    fn layer_zero_inherits_only_inside_insert() {
        assert_eq!(effective_layer("0", LayerContext::Root).unwrap(), "0");
        assert_eq!(
            effective_layer(
                "0",
                LayerContext::Insert {
                    effective_layer: "A"
                }
            )
            .unwrap(),
            "A"
        );
        assert_eq!(
            effective_layer(
                "Walls",
                LayerContext::Insert {
                    effective_layer: "A"
                }
            )
            .unwrap(),
            "Walls"
        );
    }

    #[test]
    fn empty_layer_names_reject() {
        assert_eq!(
            effective_layer("", LayerContext::Root).unwrap_err().code(),
            "invalid_layer_name"
        );
        assert_eq!(
            effective_layer(
                "0",
                LayerContext::Insert {
                    effective_layer: ""
                }
            )
            .unwrap_err()
            .code(),
            "invalid_layer_name"
        );
    }

    #[test]
    fn nested_layer_zero_resolves_one_insert_level_at_a_time() {
        let outer_insert_layer = effective_layer("A", LayerContext::Root).unwrap();
        let inner_insert_layer = effective_layer(
            "0",
            LayerContext::Insert {
                effective_layer: outer_insert_layer,
            },
        )
        .unwrap();
        let entity_layer = effective_layer(
            "0",
            LayerContext::Insert {
                effective_layer: inner_insert_layer,
            },
        )
        .unwrap();
        assert_eq!(entity_layer, "A");
    }

    #[test]
    fn nested_nonzero_insert_layer_overrides_outer_layer() {
        let outer_insert_layer = effective_layer("A", LayerContext::Root).unwrap();
        let inner_insert_layer = effective_layer(
            "B",
            LayerContext::Insert {
                effective_layer: outer_insert_layer,
            },
        )
        .unwrap();
        let entity_layer = effective_layer(
            "0",
            LayerContext::Insert {
                effective_layer: inner_insert_layer,
            },
        )
        .unwrap();
        assert_eq!(entity_layer, "B");
    }

    #[test]
    fn nested_by_block_chains_already_resolved_insert_values() {
        let outer = Property::Explicit("red")
            .resolve(&PropertyContext::new("blue", None))
            .unwrap();
        let inner = Property::ByBlock
            .resolve(&PropertyContext::new("green", Some(outer)))
            .unwrap();
        let entity = Property::ByBlock
            .resolve(&PropertyContext::new("yellow", Some(inner)))
            .unwrap();
        assert_eq!(entity, "red");
    }
}
