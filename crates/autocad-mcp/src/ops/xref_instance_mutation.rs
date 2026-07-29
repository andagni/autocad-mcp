use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::autocad_reader::contract::xrefs::XrefInstanceListOptions;
use crate::certification::XrefMutationOperation;
use crate::ops::{
    xref_attachment_mutation::{XrefAttachmentMutationSnapshot, XrefPreservationVerification},
    xref_io,
    xref_mutation::{
        XrefLockedMutationContext, XrefMutationEngineBoundary, XrefMutationOperationCallback,
        XrefOperationContext, XrefTransactionError, XrefTransactionErrorCode,
        XrefVerificationContext,
    },
    xrefs::{
        self, classify_instance_update_property, DeleteXrefInstanceRequest,
        DeleteXrefInstanceResponse, DeleteXrefInstanceStatus, InsertXrefInstanceRequest,
        InsertXrefInstanceResponse, InsertXrefInstanceStatus, InsertionUnit,
        PersistedInsertionUnits, UpdateXrefInstanceRequest, UpdateXrefInstanceResponse,
        UpdateXrefInstanceStatus, XrefAttachmentRecord, XrefError, XrefInstancePlacement,
        XrefInstanceRecord, XrefPlacementKind, XrefPoint3, XrefPropertyClassification,
        XrefRectangularArray, XrefScale3, XrefUnitAssumptions, XrefUnitBasis, XrefUnitScaling,
        XrefUnitValue, XrefVector3, XrefVisibility,
    },
};

const INSERT_SCRIPT_NAME: &str = "insert-xref-instance.lsp";
const INSERT_SENTINEL_NAME: &str = "insert-xref-instance-result.json";
const UPDATE_SCRIPT_NAME: &str = "update-xref-instance.lsp";
const UPDATE_SENTINEL_NAME: &str = "update-xref-instance-result.json";
const DELETE_SCRIPT_NAME: &str = "delete-xref-instance.lsp";
const DELETE_SENTINEL_NAME: &str = "delete-xref-instance-result.json";

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum XrefOwnerWriteState {
    Writable,
    XrefDefinition,
    XrefDependent,
    Anonymous,
    Dynamic,
    AutocadManaged,
    ReadOnly,
    Unsupported,
}

impl XrefOwnerWriteState {
    fn is_writable(self) -> bool {
        self == Self::Writable
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct XrefInstanceOwnerFacts {
    pub handle: String,
    pub owner_type: xrefs::XrefOwnerType,
    pub name: String,
    pub write_state: XrefOwnerWriteState,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum XrefLayerOwnership {
    HostOwned,
    XrefDependent,
    Unsupported,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct XrefInstanceLayerFacts {
    pub handle: String,
    pub name: String,
    pub ownership: XrefLayerOwnership,
    pub locked: bool,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum XrefInstanceClipFacts {
    Absent,
    Present { fingerprint: String },
    Unobservable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct XrefInstanceUnitFacts {
    pub host_units: PersistedInsertionUnits,
    pub attachment_units: BTreeMap<String, PersistedInsertionUnits>,
    pub host_unobservable_uses_profile_default: bool,
    pub source_unobservable_uses_profile_default: BTreeSet<String>,
    pub supported_profile_default_units: Vec<InsertionUnit>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct XrefInstanceMutationEnvironment {
    pub owners: Vec<XrefInstanceOwnerFacts>,
    pub layers: Vec<XrefInstanceLayerFacts>,
    pub block_references: BTreeMap<String, Vec<String>>,
    pub block_reference_graph_complete: bool,
    pub clips: BTreeMap<String, XrefInstanceClipFacts>,
    pub units: XrefInstanceUnitFacts,
}

pub(crate) trait XrefInstanceMutationFactSource {
    fn read_environment(
        &mut self,
        host: &xref_io::LoadedXrefHost,
    ) -> Result<XrefInstanceMutationEnvironment, XrefTransactionError>;

    fn read_preservation_snapshot(
        &mut self,
        host: &xref_io::LoadedXrefHost,
    ) -> Result<XrefAttachmentMutationSnapshot, XrefTransactionError>;

    fn verify_preservation(
        &mut self,
        verification: &XrefPreservationVerification<'_>,
    ) -> Result<(), XrefTransactionError>;
}

pub(crate) trait XrefInstanceMutationReader {
    fn list_attachments(
        &mut self,
        path: &Path,
    ) -> Result<Vec<XrefAttachmentRecord>, XrefTransactionError>;

    fn get_instance(
        &mut self,
        path: &Path,
        handle: &str,
    ) -> Result<Option<XrefInstanceRecord>, XrefTransactionError>;

    fn list_attachment_instances(
        &mut self,
        path: &Path,
        attachment_handle: &str,
    ) -> Result<Vec<XrefInstanceRecord>, XrefTransactionError>;

    fn read_environment(
        &mut self,
        path: &Path,
    ) -> Result<XrefInstanceMutationEnvironment, XrefTransactionError>;

    fn read_preservation_snapshot(
        &mut self,
        path: &Path,
    ) -> Result<XrefAttachmentMutationSnapshot, XrefTransactionError>;

    fn verify_preservation(
        &mut self,
        verification: &XrefPreservationVerification<'_>,
    ) -> Result<(), XrefTransactionError>;
}

#[derive(Debug, Clone)]
pub(crate) struct PortableXrefInstanceMutationReader<Facts> {
    facts: Facts,
    hosts: HashMap<PathBuf, xref_io::LoadedXrefHost>,
}

impl<Facts> PortableXrefInstanceMutationReader<Facts> {
    pub(crate) fn new(facts: Facts) -> Self {
        Self {
            facts,
            hosts: HashMap::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn into_fact_source(self) -> Facts {
        self.facts
    }

    fn ensure_host(&mut self, path: &Path, tool: &str) -> Result<(), XrefTransactionError> {
        if !self.hosts.contains_key(path) {
            let host = xref_io::load_xref_host(path, tool).map_err(transaction_error_from_xref)?;
            self.hosts.insert(path.to_path_buf(), host);
        }
        Ok(())
    }
}

impl<Facts> XrefInstanceMutationReader for PortableXrefInstanceMutationReader<Facts>
where
    Facts: XrefInstanceMutationFactSource,
{
    fn list_attachments(
        &mut self,
        path: &Path,
    ) -> Result<Vec<XrefAttachmentRecord>, XrefTransactionError> {
        self.ensure_host(path, "list_xrefs")?;
        self.hosts
            .get(path)
            .expect("host was inserted")
            .attachments()
            .map_err(transaction_error_from_xref)
    }

    fn get_instance(
        &mut self,
        path: &Path,
        handle: &str,
    ) -> Result<Option<XrefInstanceRecord>, XrefTransactionError> {
        self.ensure_host(path, "get_xref_instance")?;
        match self
            .hosts
            .get(path)
            .expect("host was inserted")
            .get_instance(handle)
        {
            Ok(instance) => Ok(Some(instance)),
            Err(error) if error.code() == xrefs::xref_failure_code::XREF_INSTANCE_NOT_FOUND => {
                Ok(None)
            }
            Err(error) => Err(transaction_error_from_xref(error)),
        }
    }

    fn list_attachment_instances(
        &mut self,
        path: &Path,
        attachment_handle: &str,
    ) -> Result<Vec<XrefInstanceRecord>, XrefTransactionError> {
        self.ensure_host(path, "list_xref_instances")?;
        self.hosts
            .get(path)
            .expect("host was inserted")
            .instances(&XrefInstanceListOptions {
                attachment_handle: Some(attachment_handle.to_string()),
                attachment_name: None,
                owner_handle: None,
                owner_type: None,
                owner_name: None,
                layer_handle: None,
                layer_name: None,
                visibility: None,
            })
            .map_err(transaction_error_from_xref)
    }

    fn read_environment(
        &mut self,
        path: &Path,
    ) -> Result<XrefInstanceMutationEnvironment, XrefTransactionError> {
        self.ensure_host(path, "xref_mutation")?;
        let host = self.hosts.get(path).expect("host was inserted");
        self.facts.read_environment(host)
    }

    fn read_preservation_snapshot(
        &mut self,
        path: &Path,
    ) -> Result<XrefAttachmentMutationSnapshot, XrefTransactionError> {
        self.ensure_host(path, "xref_mutation")?;
        let host = self.hosts.get(path).expect("host was inserted");
        self.facts.read_preservation_snapshot(host)
    }

    fn verify_preservation(
        &mut self,
        verification: &XrefPreservationVerification<'_>,
    ) -> Result<(), XrefTransactionError> {
        self.facts.verify_preservation(verification)
    }
}

fn transaction_error_from_xref(error: XrefError) -> XrefTransactionError {
    domain_error(error.code(), error.to_string())
}

fn domain_error(code: &str, detail: impl Into<String>) -> XrefTransactionError {
    XrefTransactionError::new(XrefTransactionErrorCode::Domain(code.to_string()), detail)
}

fn verification_error(detail: impl Into<String>) -> XrefTransactionError {
    XrefTransactionError::new(XrefTransactionErrorCode::VerificationFailed, detail)
}

fn write_error(detail: impl Into<String>) -> XrefTransactionError {
    XrefTransactionError::new(XrefTransactionErrorCode::WriteFailed, detail)
}

fn canonical_handle(value: &str) -> Result<String, XrefTransactionError> {
    xrefs::canonical_input_handle(value).map_err(transaction_error_from_xref)
}

fn canonical_optional_handle(
    value: &Option<String>,
) -> Result<Option<String>, XrefTransactionError> {
    value.as_deref().map(canonical_handle).transpose()
}

fn validate_absolute_drawing_path(path: &str) -> Result<(), XrefTransactionError> {
    if Path::new(path).is_absolute() {
        Ok(())
    } else {
        Err(domain_error(
            xrefs::xref_failure_code::DRAWING_UNREADABLE,
            "drawing_path must be an absolute local path",
        ))
    }
}

fn validate_context_path(requested: &str, actual: &Path) -> Result<String, XrefTransactionError> {
    if Path::new(requested) != actual {
        return Err(domain_error(
            xrefs::xref_failure_code::INVALID_PARAMETERS,
            format!(
                "operation drawing_path '{}' does not match locked host '{}'",
                requested,
                actual.display()
            ),
        ));
    }
    Ok(actual.to_string_lossy().into_owned())
}

fn validate_attachment_records(
    records: Vec<XrefAttachmentRecord>,
) -> Result<Vec<XrefAttachmentRecord>, XrefTransactionError> {
    for record in &records {
        record.validate().map_err(transaction_error_from_xref)?;
    }
    Ok(records)
}

fn canonical_instance(
    record: XrefInstanceRecord,
) -> Result<XrefInstanceRecord, XrefTransactionError> {
    record.canonicalized().map_err(transaction_error_from_xref)
}

fn canonical_instances(
    records: Vec<XrefInstanceRecord>,
) -> Result<Vec<XrefInstanceRecord>, XrefTransactionError> {
    records.into_iter().map(canonical_instance).collect()
}

fn resolve_attachment(
    records: &[XrefAttachmentRecord],
    handle: Option<&str>,
    name: Option<&str>,
) -> Result<XrefAttachmentRecord, XrefTransactionError> {
    if handle.is_none() && name.is_none_or(|name| name.trim().is_empty()) {
        return Err(domain_error(
            xrefs::xref_failure_code::MISSING_IDENTITY,
            "insert_xref_instance requires attachment_handle, attachment_name, or both",
        ));
    }

    let by_handle = handle
        .map(|handle| {
            records
                .iter()
                .find(|record| record.handle == handle)
                .cloned()
                .ok_or_else(|| {
                    domain_error(
                        xrefs::xref_failure_code::XREF_NOT_FOUND,
                        format!("direct XREF attachment handle '{handle}' was not found"),
                    )
                })
        })
        .transpose()?;

    let by_name = name
        .map(|name| {
            let matches = records
                .iter()
                .filter(|record| xrefs::xref_name_eq(&record.name, name))
                .cloned()
                .collect::<Vec<_>>();
            match matches.as_slice() {
                [record] => Ok(record.clone()),
                [] => Err(domain_error(
                    xrefs::xref_failure_code::XREF_NOT_FOUND,
                    format!("direct XREF attachment name '{name}' was not found"),
                )),
                _ => Err(domain_error(
                    xrefs::xref_failure_code::AMBIGUOUS_IDENTITY,
                    format!("direct XREF attachment name '{name}' is ambiguous"),
                )),
            }
        })
        .transpose()?;

    match (by_handle, by_name) {
        (Some(by_handle), Some(by_name)) if by_handle.handle != by_name.handle => {
            Err(domain_error(
                xrefs::xref_failure_code::CONTRADICTORY_IDENTITY,
                "attachment handle and name resolve to different direct attachments",
            ))
        }
        (Some(record), _) | (_, Some(record)) => Ok(record),
        (None, None) => Err(domain_error(
            xrefs::xref_failure_code::MISSING_IDENTITY,
            "insert_xref_instance requires a usable attachment selector",
        )),
    }
}

fn resolve_owner(
    environment: &XrefInstanceMutationEnvironment,
    placement: &XrefInstancePlacement,
) -> Result<XrefInstanceOwnerFacts, XrefTransactionError> {
    let (handle, semantic) = match (
        placement.owner_handle.as_deref(),
        placement.owner_type,
        placement.owner_name.as_deref(),
    ) {
        (None, None, None) => (None, Some((xrefs::XrefOwnerType::ModelSpace, "Model"))),
        (Some(handle), None, None) => (Some(handle), None),
        (None, Some(owner_type), Some(name)) => (None, Some((owner_type, name))),
        (Some(handle), Some(owner_type), Some(name)) => (Some(handle), Some((owner_type, name))),
        _ => {
            return Err(domain_error(
                xrefs::xref_failure_code::INVALID_XREF_OWNER,
                "owner selector must be {}, {owner_handle}, {owner_type,owner_name}, or all three",
            ))
        }
    };

    let by_handle = handle
        .map(|handle| {
            environment
                .owners
                .iter()
                .find(|owner| owner.handle == handle)
                .cloned()
                .ok_or_else(|| {
                    domain_error(
                        xrefs::xref_failure_code::XREF_OWNER_NOT_FOUND,
                        format!("XREF owner handle '{handle}' was not found"),
                    )
                })
        })
        .transpose()?;

    let by_semantic = semantic
        .map(|(owner_type, name)| {
            let matches = environment
                .owners
                .iter()
                .filter(|owner| {
                    owner.owner_type == owner_type && xrefs::xref_name_eq(&owner.name, name)
                })
                .cloned()
                .collect::<Vec<_>>();
            match matches.as_slice() {
                [owner] => Ok(owner.clone()),
                [] => Err(domain_error(
                    xrefs::xref_failure_code::XREF_OWNER_NOT_FOUND,
                    format!("semantic XREF owner '{name}' was not found"),
                )),
                _ => Err(domain_error(
                    xrefs::xref_failure_code::UNSUPPORTED_XREF_OWNER,
                    format!("semantic XREF owner '{name}' is not unique"),
                )),
            }
        })
        .transpose()?;

    let owner = match (by_handle, by_semantic) {
        (Some(by_handle), Some(by_semantic)) if by_handle.handle != by_semantic.handle => {
            return Err(domain_error(
                xrefs::xref_failure_code::CONTRADICTORY_IDENTITY,
                "owner handle and semantic selector resolve to different owners",
            ))
        }
        (Some(owner), _) | (_, Some(owner)) => owner,
        (None, None) => unreachable!("default owner always supplies semantic identity"),
    };

    if !owner.write_state.is_writable() {
        return Err(domain_error(
            xrefs::xref_failure_code::UNSUPPORTED_XREF_OWNER,
            format!(
                "owner '{}' ({}) is not writable: {:?}",
                owner.name, owner.handle, owner.write_state
            ),
        ));
    }
    Ok(owner)
}

fn owner_for_existing_instance(
    environment: &XrefInstanceMutationEnvironment,
    instance: &XrefInstanceRecord,
) -> Result<XrefInstanceOwnerFacts, XrefTransactionError> {
    let Some(owner) = environment
        .owners
        .iter()
        .find(|owner| owner.handle == instance.owner_handle)
        .cloned()
    else {
        return Err(domain_error(
            xrefs::xref_failure_code::UNSUPPORTED_XREF_OWNER,
            format!(
                "existing instance owner '{}' cannot be proven writable",
                instance.owner_handle
            ),
        ));
    };
    if owner.owner_type != instance.owner_type
        || !xrefs::xref_name_eq(&owner.name, &instance.owner_name)
        || !owner.write_state.is_writable()
    {
        return Err(domain_error(
            xrefs::xref_failure_code::UNSUPPORTED_XREF_OWNER,
            format!(
                "existing instance owner '{}' is unsupported or contradicts its persisted record",
                instance.owner_handle
            ),
        ));
    }
    Ok(owner)
}

fn resolve_layer(
    environment: &XrefInstanceMutationEnvironment,
    handle: Option<&str>,
    name: Option<&str>,
) -> Result<XrefInstanceLayerFacts, XrefTransactionError> {
    let default_name = if handle.is_none() && name.is_none() {
        Some("0")
    } else {
        name
    };
    let by_handle = handle
        .map(|handle| {
            environment
                .layers
                .iter()
                .find(|layer| layer.handle == handle)
                .cloned()
                .ok_or_else(|| {
                    domain_error(
                        xrefs::xref_failure_code::LAYER_NOT_FOUND,
                        format!("layer handle '{handle}' was not found"),
                    )
                })
        })
        .transpose()?;
    let by_name = default_name
        .map(|name| {
            let matches = environment
                .layers
                .iter()
                .filter(|layer| xrefs::xref_name_eq(&layer.name, name))
                .cloned()
                .collect::<Vec<_>>();
            match matches.as_slice() {
                [layer] => Ok(layer.clone()),
                [] => Err(domain_error(
                    xrefs::xref_failure_code::LAYER_NOT_FOUND,
                    format!("layer name '{name}' was not found"),
                )),
                _ => Err(domain_error(
                    xrefs::xref_failure_code::CONTRADICTORY_IDENTITY,
                    format!("layer name '{name}' is not unique"),
                )),
            }
        })
        .transpose()?;
    let layer = match (by_handle, by_name) {
        (Some(by_handle), Some(by_name)) if by_handle.handle != by_name.handle => {
            return Err(domain_error(
                xrefs::xref_failure_code::CONTRADICTORY_IDENTITY,
                "layer handle and name resolve to different layers",
            ))
        }
        (Some(layer), _) | (_, Some(layer)) => layer,
        (None, None) => unreachable!("default layer always supplies a name"),
    };
    if layer.ownership != XrefLayerOwnership::HostOwned {
        return Err(domain_error(
            xrefs::xref_failure_code::LAYER_NOT_HOST_OWNED,
            format!("layer '{}' is not host-owned", layer.name),
        ));
    }
    Ok(layer)
}

fn layer_for_existing_instance(
    environment: &XrefInstanceMutationEnvironment,
    instance: &XrefInstanceRecord,
) -> Result<XrefInstanceLayerFacts, XrefTransactionError> {
    let layer = resolve_layer(
        environment,
        Some(&instance.layer_handle),
        Some(&instance.layer_name),
    )?;
    if layer.locked {
        return Err(domain_error(
            xrefs::xref_failure_code::XREF_INSTANCE_LOCKED,
            format!(
                "instance '{}' is on locked layer '{}'",
                instance.handle, layer.name
            ),
        ));
    }
    Ok(layer)
}

fn would_create_recursive_ownership(
    environment: &XrefInstanceMutationEnvironment,
    attachment_handle: &str,
    owner: &XrefInstanceOwnerFacts,
) -> Result<bool, XrefTransactionError> {
    if owner.owner_type != xrefs::XrefOwnerType::BlockDefinition {
        return Ok(false);
    }
    if !environment.block_reference_graph_complete {
        return Err(domain_error(
            xrefs::xref_failure_code::UNSUPPORTED_XREF_DATA,
            "block-reference graph is incomplete; recursive ownership cannot be excluded",
        ));
    }
    if attachment_handle == owner.handle {
        return Ok(true);
    }

    let mut pending = vec![attachment_handle];
    let mut visited = BTreeSet::new();
    while let Some(current) = pending.pop() {
        if !visited.insert(current.to_string()) {
            continue;
        }
        for referenced in environment
            .block_references
            .get(current)
            .into_iter()
            .flatten()
        {
            if referenced == &owner.handle {
                return Ok(true);
            }
            pending.push(referenced);
        }
    }
    Ok(false)
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct ResolvedUnitFactor {
    source_units: XrefUnitValue,
    host_units: XrefUnitValue,
    factor: f64,
}

fn unit_name(unit: InsertionUnit) -> &'static str {
    match unit {
        InsertionUnit::Unitless => "unitless",
        InsertionUnit::Inches => "inches",
        InsertionUnit::Feet => "feet",
        InsertionUnit::Miles => "miles",
        InsertionUnit::Millimeters => "millimeters",
        InsertionUnit::Centimeters => "centimeters",
        InsertionUnit::Meters => "meters",
        InsertionUnit::Kilometers => "kilometers",
        InsertionUnit::Microinches => "microinches",
        InsertionUnit::Mils => "mils",
        InsertionUnit::Yards => "yards",
        InsertionUnit::Angstroms => "angstroms",
        InsertionUnit::Nanometers => "nanometers",
        InsertionUnit::Microns => "microns",
        InsertionUnit::Decimeters => "decimeters",
        InsertionUnit::Dekameters => "dekameters",
        InsertionUnit::Hectometers => "hectometers",
        InsertionUnit::Gigameters => "gigameters",
        InsertionUnit::AstronomicalUnits => "astronomical_units",
        InsertionUnit::LightYears => "light_years",
        InsertionUnit::Parsecs => "parsecs",
        InsertionUnit::UsSurveyFeet => "us_survey_feet",
        InsertionUnit::UsSurveyInches => "us_survey_inches",
        InsertionUnit::UsSurveyYards => "us_survey_yards",
        InsertionUnit::UsSurveyMiles => "us_survey_miles",
    }
}

pub(crate) fn xref_instance_unit_profile_defaults(
    assumptions: Option<&XrefUnitAssumptions>,
) -> BTreeMap<String, String> {
    let mut defaults = BTreeMap::new();
    if let Some(source_units) = assumptions.and_then(|value| value.source_units) {
        defaults.insert(
            "source_units".to_string(),
            unit_name(source_units).to_string(),
        );
    }
    if let Some(host_units) = assumptions.and_then(|value| value.host_units) {
        defaults.insert("host_units".to_string(), unit_name(host_units).to_string());
    }
    defaults
}

fn metres_per_unit(unit: InsertionUnit) -> Option<f64> {
    Some(match unit {
        InsertionUnit::Unitless => return None,
        InsertionUnit::Inches => 0.0254,
        InsertionUnit::Feet => 0.3048,
        InsertionUnit::Miles => 1609.344,
        InsertionUnit::Millimeters => 0.001,
        InsertionUnit::Centimeters => 0.01,
        InsertionUnit::Meters => 1.0,
        InsertionUnit::Kilometers => 1000.0,
        InsertionUnit::Microinches => 0.000_000_025_4,
        InsertionUnit::Mils => 0.000_025_4,
        InsertionUnit::Yards => 0.9144,
        InsertionUnit::Angstroms => 1e-10,
        InsertionUnit::Nanometers => 1e-9,
        InsertionUnit::Microns => 1e-6,
        InsertionUnit::Decimeters => 0.1,
        InsertionUnit::Dekameters => 10.0,
        InsertionUnit::Hectometers => 100.0,
        InsertionUnit::Gigameters => 1e9,
        InsertionUnit::AstronomicalUnits => 149_597_870_700.0,
        InsertionUnit::LightYears => 9_460_730_472_580_800.0,
        InsertionUnit::Parsecs => 30_856_775_814_913_672.0,
        InsertionUnit::UsSurveyFeet => 1200.0 / 3937.0,
        InsertionUnit::UsSurveyInches => 100.0 / 3937.0,
        InsertionUnit::UsSurveyYards => 3600.0 / 3937.0,
        InsertionUnit::UsSurveyMiles => 6_336_000.0 / 3937.0,
    })
}

fn same_factor(left: ResolvedUnitFactor, right: ResolvedUnitFactor) -> bool {
    left.source_units == right.source_units
        && left.host_units == right.host_units
        && float_eq(left.factor, right.factor)
}

fn surviving_unit_factor(
    instances: &[XrefInstanceRecord],
) -> Result<Option<ResolvedUnitFactor>, XrefTransactionError> {
    let mut resolved = None;
    for instance in instances {
        let XrefUnitScaling::Available {
            source_units,
            host_units,
            factor,
            ..
        } = instance.unit_scaling
        else {
            continue;
        };
        let candidate = ResolvedUnitFactor {
            source_units,
            host_units,
            factor,
        };
        if let Some(existing) = resolved {
            if !same_factor(existing, candidate) {
                return Err(domain_error(
                    xrefs::xref_failure_code::UNSUPPORTED_XREF_DATA,
                    "surviving XREF instances disagree about automatic unit factor or basis",
                ));
            }
        } else {
            resolved = Some(candidate);
        }
    }
    Ok(resolved)
}

#[derive(Debug, Clone, Copy)]
enum UnitSideResolution {
    Proven(InsertionUnit),
    Assumable,
}

fn classify_unit_side(
    persisted: PersistedInsertionUnits,
    unobservable_uses_profile_default: bool,
    role: &str,
) -> Result<UnitSideResolution, XrefTransactionError> {
    match persisted {
        PersistedInsertionUnits::Known { value } if value != InsertionUnit::Unitless => {
            Ok(UnitSideResolution::Proven(value))
        }
        PersistedInsertionUnits::Known { .. } => Err(domain_error(
            xrefs::xref_failure_code::UNSUPPORTED_XREF_DATA,
            format!("{role} units encode unitless as a non-unitless known value"),
        )),
        PersistedInsertionUnits::Unitless => Ok(UnitSideResolution::Assumable),
        PersistedInsertionUnits::UnknownCode { code } => Err(domain_error(
            xrefs::xref_failure_code::UNSUPPORTED_INSERTION_UNITS,
            format!("{role} insertion-unit code {code} is unsupported"),
        )),
        PersistedInsertionUnits::Unobservable if unobservable_uses_profile_default => {
            Ok(UnitSideResolution::Assumable)
        }
        PersistedInsertionUnits::Unobservable => Err(domain_error(
            xrefs::xref_failure_code::UNSUPPORTED_INSERTION_UNITS,
            format!("{role} insertion units are unobservable and not profile-default-applicable"),
        )),
    }
}

fn resolve_unit_side(
    resolution: UnitSideResolution,
    assumption: Option<InsertionUnit>,
    role: &str,
    facts: &XrefInstanceUnitFacts,
) -> Result<XrefUnitValue, XrefTransactionError> {
    match (resolution, assumption) {
        (UnitSideResolution::Proven(_), Some(_)) => Err(domain_error(
            xrefs::xref_failure_code::INVALID_UNIT_ASSUMPTIONS,
            format!("{role}_units is forbidden because persisted units are proven"),
        )),
        (UnitSideResolution::Proven(value), None) => Ok(XrefUnitValue {
            value,
            basis: XrefUnitBasis::Drawing,
        }),
        (UnitSideResolution::Assumable, None) => Err(domain_error(
            xrefs::xref_failure_code::AMBIGUOUS_INSERTION_UNITS,
            format!("{role}_units is required for an assumable unit role"),
        )),
        (UnitSideResolution::Assumable, Some(value)) => {
            if value != InsertionUnit::Unitless
                && !facts.supported_profile_default_units.contains(&value)
            {
                return Err(domain_error(
                    xrefs::xref_failure_code::UNSUPPORTED_INSERTION_UNITS,
                    format!(
                        "{} is not supported as an isolated AutoCAD {role} default",
                        unit_name(value)
                    ),
                ));
            }
            Ok(XrefUnitValue {
                value,
                basis: XrefUnitBasis::Request,
            })
        }
    }
}

fn factor_from_unit_values(
    source_units: XrefUnitValue,
    host_units: XrefUnitValue,
) -> Result<f64, XrefTransactionError> {
    if source_units.value == InsertionUnit::Unitless || host_units.value == InsertionUnit::Unitless
    {
        return Ok(1.0);
    }
    let source = metres_per_unit(source_units.value).ok_or_else(|| {
        domain_error(
            xrefs::xref_failure_code::UNSUPPORTED_INSERTION_UNITS,
            "source insertion units do not have a certified conversion",
        )
    })?;
    let host = metres_per_unit(host_units.value).ok_or_else(|| {
        domain_error(
            xrefs::xref_failure_code::UNSUPPORTED_INSERTION_UNITS,
            "host insertion units do not have a certified conversion",
        )
    })?;
    let factor = source / host;
    if factor.is_finite() && factor > 0.0 {
        Ok(factor)
    } else {
        Err(domain_error(
            xrefs::xref_failure_code::UNSUPPORTED_INSERTION_UNITS,
            "automatic insertion-unit factor is not finite and positive",
        ))
    }
}

fn resolve_insert_unit_factor(
    attachment_handle: &str,
    instances: &[XrefInstanceRecord],
    assumptions: Option<&XrefUnitAssumptions>,
    facts: &XrefInstanceUnitFacts,
) -> Result<ResolvedUnitFactor, XrefTransactionError> {
    if let Some(surviving) = surviving_unit_factor(instances)? {
        validate_surviving_unit_assumption(
            surviving.source_units,
            assumptions.and_then(|value| value.source_units),
            "source",
            facts,
        )?;
        validate_surviving_unit_assumption(
            surviving.host_units,
            assumptions.and_then(|value| value.host_units),
            "host",
            facts,
        )?;
        if assumptions
            .is_some_and(|value| value.source_units.is_none() && value.host_units.is_none())
        {
            return Err(domain_error(
                xrefs::xref_failure_code::INVALID_UNIT_ASSUMPTIONS,
                "empty unit_assumptions is forbidden when surviving instances prove the factor",
            ));
        }
        return Ok(surviving);
    }

    let source_persisted = facts
        .attachment_units
        .get(attachment_handle)
        .copied()
        .ok_or_else(|| {
            domain_error(
                xrefs::xref_failure_code::UNSUPPORTED_INSERTION_UNITS,
                format!("attachment '{attachment_handle}' has no persisted source-unit evidence"),
            )
        })?;
    let source = classify_unit_side(
        source_persisted,
        facts
            .source_unobservable_uses_profile_default
            .contains(attachment_handle),
        "source",
    )?;
    let host = classify_unit_side(
        facts.host_units,
        facts.host_unobservable_uses_profile_default,
        "host",
    )?;
    let source_needs_assumption = matches!(source, UnitSideResolution::Assumable);
    let host_needs_assumption = matches!(host, UnitSideResolution::Assumable);
    if assumptions.is_some()
        && !source_needs_assumption
        && !host_needs_assumption
        && assumptions
            .is_some_and(|value| value.source_units.is_none() && value.host_units.is_none())
    {
        return Err(domain_error(
            xrefs::xref_failure_code::INVALID_UNIT_ASSUMPTIONS,
            "empty unit_assumptions is forbidden when persisted units prove both roles",
        ));
    }
    let source_units = resolve_unit_side(
        source,
        assumptions.and_then(|value| value.source_units),
        "source",
        facts,
    )?;
    let host_units = resolve_unit_side(
        host,
        assumptions.and_then(|value| value.host_units),
        "host",
        facts,
    )?;
    Ok(ResolvedUnitFactor {
        source_units,
        host_units,
        factor: factor_from_unit_values(source_units, host_units)?,
    })
}

fn validate_surviving_unit_assumption(
    proven: XrefUnitValue,
    assumption: Option<InsertionUnit>,
    role: &str,
    facts: &XrefInstanceUnitFacts,
) -> Result<(), XrefTransactionError> {
    match (proven.basis, assumption) {
        (XrefUnitBasis::Drawing, None) => Ok(()),
        (XrefUnitBasis::Drawing, Some(_)) => Err(domain_error(
            xrefs::xref_failure_code::INVALID_UNIT_ASSUMPTIONS,
            format!("{role}_units is forbidden by surviving drawing-basis evidence"),
        )),
        (XrefUnitBasis::Request, None) => Err(domain_error(
            xrefs::xref_failure_code::AMBIGUOUS_INSERTION_UNITS,
            format!("{role}_units is required to reproduce surviving request-basis evidence"),
        )),
        (XrefUnitBasis::Request, Some(value)) if value != proven.value => Err(domain_error(
            xrefs::xref_failure_code::INVALID_UNIT_ASSUMPTIONS,
            format!("{role}_units disagrees with surviving request-basis evidence"),
        )),
        (XrefUnitBasis::Request, Some(value))
            if value != InsertionUnit::Unitless
                && !facts.supported_profile_default_units.contains(&value) =>
        {
            Err(domain_error(
                xrefs::xref_failure_code::UNSUPPORTED_INSERTION_UNITS,
                format!(
                    "{} is not supported as an isolated AutoCAD {role} default",
                    unit_name(value)
                ),
            ))
        }
        (XrefUnitBasis::Request, Some(_)) => Ok(()),
    }
}

fn unit_scaling_for(
    factor: ResolvedUnitFactor,
    scale: XrefScale3,
) -> Result<XrefUnitScaling, XrefTransactionError> {
    let effective_scale = XrefScale3 {
        x: scale.x * factor.factor,
        y: scale.y * factor.factor,
        z: scale.z * factor.factor,
    };
    if !effective_scale.x.is_finite()
        || !effective_scale.y.is_finite()
        || !effective_scale.z.is_finite()
    {
        return Err(domain_error(
            xrefs::xref_failure_code::INVALID_XREF_SCALE,
            "explicit scale times automatic unit factor is not finite",
        ));
    }
    Ok(XrefUnitScaling::Available {
        source_units: factor.source_units,
        host_units: factor.host_units,
        factor: factor.factor,
        effective_scale,
    })
}

fn factor_from_scaling(scaling: XrefUnitScaling) -> Option<ResolvedUnitFactor> {
    match scaling {
        XrefUnitScaling::Available {
            source_units,
            host_units,
            factor,
            ..
        } => Some(ResolvedUnitFactor {
            source_units,
            host_units,
            factor,
        }),
        XrefUnitScaling::Unavailable => None,
    }
}

fn float_eq(left: f64, right: f64) -> bool {
    (left - right).abs() <= 1e-12 * left.abs().max(right.abs()).max(1.0)
}

fn validate_clip_policy(
    context: &XrefLockedMutationContext<'_>,
    facts: &XrefInstanceClipFacts,
    handle: &str,
) -> Result<Option<String>, XrefTransactionError> {
    match facts {
        XrefInstanceClipFacts::Absent => Ok(None),
        XrefInstanceClipFacts::Present { fingerprint }
            if !context.admission.rejects_clipped_targets()
                && context.admission.clip_profile.is_some() =>
        {
            Ok(Some(fingerprint.clone()))
        }
        XrefInstanceClipFacts::Present { .. } | XrefInstanceClipFacts::Unobservable => {
            Err(domain_error(
                xrefs::xref_failure_code::UNSUPPORTED_XREF_CLIP_DATA,
                format!(
                    "clip lifecycle for instance '{handle}' is not admitted by a passing verifier profile"
                ),
            ))
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
struct ParsedUpdateProperties {
    insertion_point: Option<XrefPoint3>,
    scale: Option<XrefScale3>,
    rotation_degrees: Option<f64>,
    normal: Option<XrefVector3>,
    layer_handle: Option<String>,
    layer_name: Option<String>,
    visibility: Option<XrefVisibility>,
    array: Option<XrefRectangularArray>,
}

fn property_shape_error(key: &str, detail: impl Into<String>) -> XrefTransactionError {
    let code = match key {
        "scale" => xrefs::xref_failure_code::INVALID_XREF_SCALE,
        "normal" => xrefs::xref_failure_code::INVALID_XREF_NORMAL,
        "insertion_point" | "rotation_degrees" | "visibility" | "array" => {
            xrefs::xref_failure_code::INVALID_XREF_PLACEMENT
        }
        _ => xrefs::xref_failure_code::INVALID_XREF_PROPERTY,
    };
    domain_error(code, detail)
}

fn parse_property<T: for<'de> Deserialize<'de>>(
    key: &str,
    value: &serde_json::Value,
) -> Result<T, XrefTransactionError> {
    serde_json::from_value(value.clone()).map_err(|error| {
        property_shape_error(key, format!("invalid value for properties.{key}: {error}"))
    })
}

fn parse_update_properties(
    request: &UpdateXrefInstanceRequest,
) -> Result<ParsedUpdateProperties, XrefTransactionError> {
    if request.properties.is_empty() {
        return Err(domain_error(
            xrefs::xref_failure_code::EMPTY_XREF_UPDATE,
            "update_xref_instance.properties must contain at least one property",
        ));
    }
    for key in request.properties.keys() {
        if classify_instance_update_property(key) == XrefPropertyClassification::Unknown {
            return Err(domain_error(
                xrefs::xref_failure_code::INVALID_XREF_PROPERTY,
                format!("unknown XREF instance property '{key}'"),
            ));
        }
    }
    for key in request.properties.keys() {
        if classify_instance_update_property(key) == XrefPropertyClassification::Unsupported {
            return Err(domain_error(
                xrefs::xref_failure_code::UNSUPPORTED_XREF_PROPERTY,
                format!("XREF instance property '{key}' is read-only or unsupported"),
            ));
        }
    }

    let mut parsed = ParsedUpdateProperties::default();
    for (key, value) in &request.properties {
        match key.as_str() {
            "insertion_point" => parsed.insertion_point = Some(parse_property(key, value)?),
            "scale" => parsed.scale = Some(parse_property(key, value)?),
            "rotation_degrees" => parsed.rotation_degrees = Some(parse_property(key, value)?),
            "normal" => parsed.normal = Some(parse_property(key, value)?),
            "layer_handle" => {
                let handle = value.as_str().ok_or_else(|| {
                    domain_error(
                        xrefs::xref_failure_code::INVALID_PARAMETERS,
                        "properties.layer_handle must be a JSON string",
                    )
                })?;
                parsed.layer_handle = Some(handle.to_string());
            }
            "layer_name" => {
                parsed.layer_name = Some(
                    value
                        .as_str()
                        .ok_or_else(|| {
                            domain_error(
                                xrefs::xref_failure_code::INVALID_XREF_PROPERTY,
                                "properties.layer_name must be a string",
                            )
                        })?
                        .to_string(),
                );
            }
            "visibility" => parsed.visibility = Some(parse_property(key, value)?),
            "array" => parsed.array = Some(parse_property(key, value)?),
            _ => unreachable!("property classification rejected every other key"),
        }
    }
    Ok(parsed)
}

fn validate_context_free_update_values(
    mut properties: ParsedUpdateProperties,
) -> Result<ParsedUpdateProperties, XrefTransactionError> {
    if let Some(point) = properties.insertion_point {
        properties.insertion_point = Some(point.validate().map_err(transaction_error_from_xref)?);
    }
    if let Some(scale) = properties.scale {
        properties.scale = Some(scale.validate().map_err(transaction_error_from_xref)?);
    }
    if let Some(rotation) = properties.rotation_degrees {
        properties.rotation_degrees =
            Some(xrefs::normalize_rotation_degrees(rotation).map_err(transaction_error_from_xref)?);
    }
    if let Some(normal) = properties.normal {
        properties.normal = Some(
            normal
                .canonical_normal()
                .map_err(transaction_error_from_xref)?,
        );
    }
    if let Some(array) = properties.array {
        properties.array = Some(array.validate().map_err(transaction_error_from_xref)?);
    }
    Ok(properties)
}

fn validate_update_values(
    properties: ParsedUpdateProperties,
    existing: &XrefInstanceRecord,
) -> Result<ParsedUpdateProperties, XrefTransactionError> {
    if properties.array.is_some() && existing.placement_kind != XrefPlacementKind::RectangularArray
    {
        return Err(domain_error(
            xrefs::xref_failure_code::INVALID_XREF_PLACEMENT,
            "properties.array cannot convert a single INSERT to MINSERT",
        ));
    }
    Ok(properties)
}

fn canonicalize_update_property_handles(
    mut properties: ParsedUpdateProperties,
) -> Result<ParsedUpdateProperties, XrefTransactionError> {
    properties.layer_handle = canonical_optional_handle(&properties.layer_handle)?;
    Ok(properties)
}

#[derive(Debug, Clone)]
struct InsertScriptPlan {
    attachment_name: String,
    owner_handle: String,
    owner_type: xrefs::XrefOwnerType,
    owner_name: String,
    layer_handle: String,
    layer_name: String,
    insertion_point: XrefPoint3,
    scale: XrefScale3,
    rotation_degrees: f64,
    normal: XrefVector3,
    visibility: XrefVisibility,
    array: Option<XrefRectangularArray>,
}

#[derive(Debug, Clone)]
struct UpdateScriptPlan {
    handle: String,
    placement_kind: XrefPlacementKind,
    properties: ParsedUpdateProperties,
    resolved_layer_name: Option<String>,
}

#[derive(Debug, Clone)]
struct DeleteScriptPlan {
    handle: String,
    placement_kind: XrefPlacementKind,
}

#[derive(Debug, Clone)]
enum XrefInstanceScriptPlan {
    Insert(InsertScriptPlan),
    Update(UpdateScriptPlan),
    Delete(DeleteScriptPlan),
}

impl XrefInstanceScriptPlan {
    fn operation_name(&self) -> &'static str {
        match self {
            Self::Insert(_) => "insert_xref_instance",
            Self::Update(_) => "update_xref_instance",
            Self::Delete(_) => "delete_xref_instance",
        }
    }

    fn render_body(&self) -> String {
        match self {
            Self::Insert(plan) => render_insert_body(plan),
            Self::Update(plan) => render_update_body(plan),
            Self::Delete(plan) => render_delete_body(plan),
        }
    }
}

fn lisp_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character => escaped.push(character),
        }
    }
    escaped.push('"');
    escaped
}

fn lisp_number(value: f64) -> String {
    debug_assert!(value.is_finite());
    if value == 0.0 {
        return "0.0".to_string();
    }
    let rendered = if value.abs() < 1e-6 || value.abs() >= 1e21 {
        format!("{value:e}")
    } else {
        value.to_string()
    };
    if rendered.contains('.') || rendered.contains('e') || rendered.contains('E') {
        rendered
    } else {
        format!("{rendered}.0")
    }
}

fn lisp_point(point: XrefPoint3) -> String {
    format!(
        "(vlax-3d-point (list {} {} {}))",
        lisp_number(point.x),
        lisp_number(point.y),
        lisp_number(point.z)
    )
}

fn lisp_vector(vector: XrefVector3) -> String {
    format!(
        "(vlax-3d-point (list {} {} {}))",
        lisp_number(vector.x),
        lisp_number(vector.y),
        lisp_number(vector.z)
    )
}

fn lisp_rotation(rotation_degrees: f64) -> String {
    format!("(* pi (/ {} 180.0))", lisp_number(rotation_degrees))
}

fn expected_object_name(placement_kind: XrefPlacementKind) -> &'static str {
    match placement_kind {
        XrefPlacementKind::Single => "AcDbBlockReference",
        XrefPlacementKind::RectangularArray => "AcDbMInsertBlock",
    }
}

fn render_insert_body(plan: &InsertScriptPlan) -> String {
    let create = if let Some(array) = plan.array {
        format!(
            "(setq object (vla-AddMInsertBlock owner {} {} {} {} {} 0.0 {} {} {} {}))",
            lisp_point(plan.insertion_point),
            lisp_string(&plan.attachment_name),
            lisp_number(plan.scale.x.abs()),
            lisp_number(plan.scale.y.abs()),
            lisp_number(plan.scale.z.abs()),
            array.rows,
            array.columns,
            lisp_number(array.row_spacing),
            lisp_number(array.column_spacing),
        )
    } else {
        format!(
            "(setq object (vla-InsertBlock owner {} {} {} {} {} 0.0))",
            lisp_point(plan.insertion_point),
            lisp_string(&plan.attachment_name),
            lisp_number(plan.scale.x.abs()),
            lisp_number(plan.scale.y.abs()),
            lisp_number(plan.scale.z.abs()),
        )
    };
    let expected_class = if plan.array.is_some() {
        "AcDbMInsertBlock"
    } else {
        "AcDbBlockReference"
    };
    let visibility = match plan.visibility {
        XrefVisibility::Visible => ":vlax-true",
        XrefVisibility::Hidden => ":vlax-false",
    };
    format!(
        "  (setq owner (acmcp-object-by-handle {}))\n\
         {create}\n\
           (if (/= (vla-get-ObjectName object) {})\n\
             (error \"created XREF instance class disagrees with request\"))\n\
           (vla-put-Layer object {})\n\
           (vla-put-XScaleFactor object {})\n\
           (vla-put-YScaleFactor object {})\n\
           (vla-put-ZScaleFactor object {})\n\
           (vla-put-Normal object {})\n\
           (vla-put-Rotation object {})\n\
           (vla-put-Visible object {})\n\
           (vla-get-Handle object)",
        lisp_string(&plan.owner_handle),
        lisp_string(expected_class),
        lisp_string(&plan.layer_name),
        lisp_number(plan.scale.x),
        lisp_number(plan.scale.y),
        lisp_number(plan.scale.z),
        lisp_vector(plan.normal),
        lisp_rotation(plan.rotation_degrees),
        visibility,
    )
}

fn render_update_body(plan: &UpdateScriptPlan) -> String {
    let mut setters = Vec::new();
    if let Some(point) = plan.properties.insertion_point {
        setters.push(format!(
            "  (vla-put-InsertionPoint object {})",
            lisp_point(point)
        ));
    }
    if let Some(scale) = plan.properties.scale {
        setters.extend([
            format!("  (vla-put-XScaleFactor object {})", lisp_number(scale.x)),
            format!("  (vla-put-YScaleFactor object {})", lisp_number(scale.y)),
            format!("  (vla-put-ZScaleFactor object {})", lisp_number(scale.z)),
        ]);
    }
    if let Some(normal) = plan.properties.normal {
        setters.push(format!("  (vla-put-Normal object {})", lisp_vector(normal)));
    }
    if let Some(rotation) = plan.properties.rotation_degrees {
        setters.push(format!(
            "  (vla-put-Rotation object {})",
            lisp_rotation(rotation)
        ));
    }
    if let Some(layer_name) = &plan.resolved_layer_name {
        setters.push(format!(
            "  (vla-put-Layer object {})",
            lisp_string(layer_name)
        ));
    }
    if let Some(visibility) = plan.properties.visibility {
        setters.push(format!(
            "  (vla-put-Visible object {})",
            match visibility {
                XrefVisibility::Visible => ":vlax-true",
                XrefVisibility::Hidden => ":vlax-false",
            }
        ));
    }
    if let Some(array) = plan.properties.array {
        setters.extend([
            format!("  (vla-put-Rows object {})", array.rows),
            format!("  (vla-put-Columns object {})", array.columns),
            format!(
                "  (vla-put-RowSpacing object {})",
                lisp_number(array.row_spacing)
            ),
            format!(
                "  (vla-put-ColumnSpacing object {})",
                lisp_number(array.column_spacing)
            ),
        ]);
    }
    format!(
        "  (setq object (acmcp-object-by-handle {}))\n\
           (if (/= (vla-get-ObjectName object) {})\n\
             (error \"persisted XREF instance class changed before update\"))\n{}\n\
           (vla-get-Handle object)",
        lisp_string(&plan.handle),
        lisp_string(expected_object_name(plan.placement_kind)),
        setters.join("\n"),
    )
}

fn render_delete_body(plan: &DeleteScriptPlan) -> String {
    format!(
        "  (setq object (acmcp-object-by-handle {}))\n\
           (if (/= (vla-get-ObjectName object) {})\n\
             (error \"persisted XREF instance class changed before delete\"))\n\
           (setq deleted-handle (vla-get-Handle object))\n\
           (vla-Delete object)\n\
           deleted-handle",
        lisp_string(&plan.handle),
        lisp_string(expected_object_name(plan.placement_kind)),
    )
}

fn render_xref_instance_script(plan: &XrefInstanceScriptPlan, sentinel_path: &Path) -> String {
    let sentinel_path = sentinel_path.to_string_lossy().replace('\\', "/");
    let operation_name = plan.operation_name();
    let body = plan.render_body();
    format!(
        "; AutoCAD-MCP deterministic XREF instance mutation\n\
         (vl-load-com)\n\
         (setq acmcp-sentinel-path {})\n\
         (setq acmcp-operation-name {})\n\
         (defun acmcp-object-by-handle (handle / entity)\n\
           (setq entity (handent handle))\n\
           (if (null entity) (error \"persisted handle was not found\"))\n\
           (vlax-ename->vla-object entity))\n\
         (defun acmcp-result-json (status handle)\n\
           (strcat \"{{\\\"schema_version\\\":1,\\\"operation\\\":\\\"\"\n\
                   acmcp-operation-name\n\
                   \"\\\",\\\"status\\\":\\\"\" status\n\
                   \"\\\",\\\"handle\\\":\\\"\" handle \"\\\"}}\"))\n\
         (defun acmcp-write-result (status handle / stream json)\n\
           (setq json (acmcp-result-json status handle))\n\
           (setq stream (open acmcp-sentinel-path \"w\"))\n\
           (if (null stream) (error \"cannot open XREF result sentinel\"))\n\
           (write-line json stream)\n\
           (close stream)\n\
           (princ (strcat \"\\nAUTOCAD_MCP_XREF_RESULT \" json \"\\n\")))\n\
         (defun acmcp-perform (/ owner object deleted-handle)\n\
         {body})\n\
         (defun autocad-mcp-xref-operation (/ result)\n\
           (setq result (vl-catch-all-apply 'acmcp-perform '()))\n\
           (if (vl-catch-all-error-p result)\n\
             (progn\n\
               (acmcp-write-result \"error\" \"\")\n\
               (princ (strcat \"\\nAUTOCAD_MCP_XREF_ERROR \"\n\
                              (vl-catch-all-error-message result) \"\\n\")))\n\
             (acmcp-write-result \"ok\" result))\n\
           (princ))\n\
         (princ)\n",
        lisp_string(&sentinel_path),
        lisp_string(operation_name),
    )
}

#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct XrefInstanceMutationSentinel {
    schema_version: u32,
    operation: String,
    status: String,
    handle: String,
}

fn read_success_sentinel(
    path: &Path,
    operation: &str,
) -> Result<XrefInstanceMutationSentinel, XrefTransactionError> {
    let bytes = fs::read(path).map_err(|error| {
        verification_error(format!(
            "read {operation} machine result sentinel '{}': {error}",
            path.display()
        ))
    })?;
    let sentinel: XrefInstanceMutationSentinel =
        serde_json::from_slice(&bytes).map_err(|error| {
            verification_error(format!(
                "parse {operation} machine result sentinel '{}': {error}",
                path.display()
            ))
        })?;
    if sentinel.schema_version != 1 || sentinel.operation != operation || sentinel.status != "ok" {
        return Err(verification_error(format!(
            "{operation} sentinel does not report the expected successful operation"
        )));
    }
    let canonical = canonical_handle(&sentinel.handle).map_err(|error| {
        verification_error(format!("{operation} sentinel has invalid handle: {error}"))
    })?;
    if canonical == "0" || canonical != sentinel.handle {
        return Err(verification_error(format!(
            "{operation} sentinel handle is not canonical and non-null"
        )));
    }
    Ok(sentinel)
}

fn stage_script(
    engine: &mut dyn XrefMutationEngineBoundary,
    context: &XrefOperationContext<'_>,
    script_name: &str,
    sentinel_name: &str,
    plan: &XrefInstanceScriptPlan,
) -> Result<(PathBuf, PathBuf), XrefTransactionError> {
    let script_path = context.staging_directory.join(script_name);
    let sentinel_path = context.staging_directory.join(sentinel_name);
    let script = render_xref_instance_script(plan, &sentinel_path);
    if sentinel_path.exists() {
        return Err(write_error(format!(
            "XREF instance result sentinel already exists: '{}'",
            sentinel_path.display()
        )));
    }
    let mut script_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&script_path)
        .map_err(|error| {
            write_error(format!(
                "create XREF instance operation script '{}': {error}",
                script_path.display()
            ))
        })?;
    script_file
        .write_all(script.as_bytes())
        .and_then(|()| script_file.sync_all())
        .map_err(|error| {
            write_error(format!(
                "persist XREF instance operation script '{}': {error}",
                script_path.display()
            ))
        })?;
    engine.execute_operation(&script_path).map_err(|error| {
        write_error(format!(
            "stage XREF instance operation script '{}': {error}",
            script_path.display()
        ))
    })?;
    Ok((script_path, sentinel_path))
}

fn attachment_by_handle(
    records: &[XrefAttachmentRecord],
    handle: &str,
) -> Result<XrefAttachmentRecord, XrefTransactionError> {
    records
        .iter()
        .find(|record| record.handle == handle)
        .cloned()
        .ok_or_else(|| {
            verification_error(format!(
                "direct attachment '{handle}' disappeared from persisted output"
            ))
        })
}

fn instance_handle_set(instances: &[XrefInstanceRecord]) -> BTreeSet<String> {
    instances
        .iter()
        .map(|instance| instance.handle.clone())
        .collect()
}

fn validate_attachment_count(
    attachment: &XrefAttachmentRecord,
    instances: &[XrefInstanceRecord],
) -> Result<(), XrefTransactionError> {
    let actual = u64::try_from(instances.len()).map_err(|_| {
        domain_error(
            xrefs::xref_failure_code::UNSUPPORTED_XREF_DATA,
            "XREF instance count does not fit the public record",
        )
    })?;
    if attachment.instance_count != actual {
        return Err(domain_error(
            xrefs::xref_failure_code::UNSUPPORTED_XREF_DATA,
            format!(
                "attachment '{}' reports instance_count={} but portable reread found {actual}",
                attachment.handle, attachment.instance_count
            ),
        ));
    }
    Ok(())
}

fn verify_attachment_count(
    attachment: &XrefAttachmentRecord,
    instances: &[XrefInstanceRecord],
    expected: u64,
) -> Result<(), XrefTransactionError> {
    let listed = u64::try_from(instances.len())
        .map_err(|_| verification_error("persisted XREF instance count does not fit u64"))?;
    if attachment.instance_count != expected || listed != expected {
        return Err(verification_error(format!(
            "attachment '{}' expected instance_count={expected}, reread record={}, listed={listed}",
            attachment.handle, attachment.instance_count
        )));
    }
    Ok(())
}

fn verify_attachments_unchanged_except_count(
    before: &[XrefAttachmentRecord],
    after: &[XrefAttachmentRecord],
    selected_handle: &str,
    selected_count: u64,
) -> Result<(), XrefTransactionError> {
    if before.len() != after.len() {
        return Err(verification_error(
            "XREF instance mutation changed the direct attachment set",
        ));
    }
    for before_record in before {
        let after_record = after
            .iter()
            .find(|candidate| candidate.handle == before_record.handle)
            .ok_or_else(|| {
                verification_error(format!(
                    "direct attachment '{}' disappeared after instance mutation",
                    before_record.handle
                ))
            })?;
        let mut expected = before_record.clone();
        if expected.handle == selected_handle {
            expected.instance_count = selected_count;
        }
        if after_record != &expected {
            return Err(verification_error(format!(
                "direct attachment '{}' changed outside the permitted instance_count update",
                before_record.handle
            )));
        }
    }
    Ok(())
}

fn scaling_matches(left: XrefUnitScaling, right: XrefUnitScaling) -> bool {
    match (left, right) {
        (XrefUnitScaling::Unavailable, XrefUnitScaling::Unavailable) => true,
        (
            XrefUnitScaling::Available {
                source_units: left_source,
                host_units: left_host,
                factor: left_factor,
                effective_scale: left_scale,
            },
            XrefUnitScaling::Available {
                source_units: right_source,
                host_units: right_host,
                factor: right_factor,
                effective_scale: right_scale,
            },
        ) => {
            left_source == right_source
                && left_host == right_host
                && float_eq(left_factor, right_factor)
                && scale_matches(left_scale, right_scale)
        }
        _ => false,
    }
}

fn point_matches(left: XrefPoint3, right: XrefPoint3) -> bool {
    float_eq(left.x, right.x) && float_eq(left.y, right.y) && float_eq(left.z, right.z)
}

fn scale_matches(left: XrefScale3, right: XrefScale3) -> bool {
    float_eq(left.x, right.x) && float_eq(left.y, right.y) && float_eq(left.z, right.z)
}

fn vector_matches(left: XrefVector3, right: XrefVector3) -> bool {
    float_eq(left.x, right.x) && float_eq(left.y, right.y) && float_eq(left.z, right.z)
}

fn records_match(left: &XrefInstanceRecord, right: &XrefInstanceRecord) -> bool {
    left.handle == right.handle
        && left.attachment_handle == right.attachment_handle
        && left.attachment_name == right.attachment_name
        && left.owner_handle == right.owner_handle
        && left.owner_type == right.owner_type
        && left.owner_name == right.owner_name
        && left.layer_handle == right.layer_handle
        && left.layer_name == right.layer_name
        && point_matches(left.insertion_point, right.insertion_point)
        && scale_matches(left.scale, right.scale)
        && float_eq(left.rotation_degrees, right.rotation_degrees)
        && vector_matches(left.normal, right.normal)
        && left.visibility == right.visibility
        && left.placement_kind == right.placement_kind
        && match (left.array, right.array) {
            (None, None) => true,
            (Some(left), Some(right)) => {
                left.rows == right.rows
                    && left.columns == right.columns
                    && float_eq(left.row_spacing, right.row_spacing)
                    && float_eq(left.column_spacing, right.column_spacing)
            }
            _ => false,
        }
        && scaling_matches(left.unit_scaling, right.unit_scaling)
}

#[derive(Debug, Clone)]
struct XrefInstancePreservationState {
    before: XrefAttachmentMutationSnapshot,
    profile_id: String,
}

fn capture_instance_preservation<Reader>(
    reader: &mut Reader,
    context: &XrefLockedMutationContext<'_>,
) -> Result<XrefInstancePreservationState, XrefTransactionError>
where
    Reader: XrefInstanceMutationReader,
{
    Ok(XrefInstancePreservationState {
        before: reader.read_preservation_snapshot(context.host_path)?,
        profile_id: context.admission.preservation_profile.profile_id.clone(),
    })
}

fn verify_instance_preservation<Reader>(
    reader: &mut Reader,
    operation: XrefMutationOperation,
    state: &XrefInstancePreservationState,
    selected_attachment_handle: &str,
    context: &XrefVerificationContext<'_>,
) -> Result<(), XrefTransactionError>
where
    Reader: XrefInstanceMutationReader,
{
    let after = reader
        .read_preservation_snapshot(context.temporary_host)
        .map_err(|error| {
            verification_error(format!(
                "read persisted whole-drawing preservation snapshot: {error}"
            ))
        })?;
    if state.before.saved_visretain != after.saved_visretain
        || state.before.saved_xrefoverride != after.saved_xrefoverride
    {
        return Err(verification_error(
            "instance mutation changed saved VISRETAIN or XREFOVERRIDE",
        ));
    }
    reader
        .verify_preservation(&XrefPreservationVerification {
            operation,
            profile_id: &state.profile_id,
            before: &state.before,
            after: &after,
            selected_attachment_handle: Some(selected_attachment_handle),
            source_graph: None,
            source_snapshots: context.source_snapshots,
        })
        .map_err(|error| {
            verification_error(format!(
                "whole-drawing instance preservation verification failed: {error}"
            ))
        })
}

fn validate_insert_placement_shape(
    placement: &XrefInstancePlacement,
) -> Result<(), XrefTransactionError> {
    match (
        placement.owner_handle.is_some(),
        placement.owner_type.is_some(),
        placement.owner_name.is_some(),
    ) {
        (false, false, false) | (true, false, false) | (false, true, true) | (true, true, true) => {
        }
        _ => {
            return Err(domain_error(
                xrefs::xref_failure_code::INVALID_XREF_OWNER,
                "owner selector must be {}, {owner_handle}, {owner_type,owner_name}, or all three",
            ))
        }
    }
    Ok(())
}

fn canonicalize_insert_placement(
    mut placement: XrefInstancePlacement,
) -> Result<XrefInstancePlacement, XrefTransactionError> {
    validate_insert_placement_shape(&placement)?;
    placement.owner_handle = canonical_optional_handle(&placement.owner_handle)?;
    placement.layer_handle = canonical_optional_handle(&placement.layer_handle)?;
    Ok(placement)
}

type ValidatedPlacementValues = (
    XrefPoint3,
    XrefScale3,
    f64,
    XrefVector3,
    XrefVisibility,
    Option<XrefRectangularArray>,
);

fn validate_insert_placement_values(
    placement: &XrefInstancePlacement,
) -> Result<ValidatedPlacementValues, XrefTransactionError> {
    let insertion_point = placement
        .insertion_point
        .unwrap_or(XrefPoint3::ORIGIN)
        .validate()
        .map_err(transaction_error_from_xref)?;
    let scale = placement
        .scale
        .unwrap_or(XrefScale3::IDENTITY)
        .validate()
        .map_err(transaction_error_from_xref)?;
    let rotation_degrees =
        xrefs::normalize_rotation_degrees(placement.rotation_degrees.unwrap_or(0.0))
            .map_err(transaction_error_from_xref)?;
    let normal = placement
        .normal
        .unwrap_or(XrefVector3::WORLD_Z)
        .canonical_normal()
        .map_err(transaction_error_from_xref)?;
    let array = placement
        .array
        .map(|array| array.validate().map_err(transaction_error_from_xref))
        .transpose()?;
    Ok((
        insertion_point,
        scale,
        rotation_degrees,
        normal,
        placement.visibility.unwrap_or(XrefVisibility::Visible),
        array,
    ))
}

#[derive(Debug, Clone)]
struct ValidatedInsert {
    drawing: String,
    pre_attachments: Vec<XrefAttachmentRecord>,
    attachment: XrefAttachmentRecord,
    pre_instances: Vec<XrefInstanceRecord>,
    script: InsertScriptPlan,
    unit_factor: ResolvedUnitFactor,
    preservation: XrefInstancePreservationState,
}

#[derive(Debug)]
pub(crate) struct InsertXrefInstanceOperation<Reader> {
    request: InsertXrefInstanceRequest,
    placement_values: ValidatedPlacementValues,
    reader: Reader,
    validated: Option<ValidatedInsert>,
    sentinel_path: Option<PathBuf>,
}

impl<Reader> InsertXrefInstanceOperation<Reader> {
    pub(crate) fn new(
        mut request: InsertXrefInstanceRequest,
        reader: Reader,
    ) -> Result<Self, XrefTransactionError> {
        let placement = request.placement.take().unwrap_or(XrefInstancePlacement {
            owner_handle: None,
            owner_type: None,
            owner_name: None,
            layer_handle: None,
            layer_name: None,
            insertion_point: None,
            scale: None,
            rotation_degrees: None,
            normal: None,
            visibility: None,
            array: None,
        });
        validate_insert_placement_shape(&placement)?;
        let placement_values = validate_insert_placement_values(&placement)?;
        validate_absolute_drawing_path(&request.drawing_path)?;
        if request.attachment_handle.is_none()
            && request
                .attachment_name
                .as_deref()
                .is_none_or(|name| name.trim().is_empty())
        {
            return Err(domain_error(
                xrefs::xref_failure_code::MISSING_IDENTITY,
                "insert_xref_instance requires attachment_handle, attachment_name, or both",
            ));
        }
        request.attachment_handle = canonical_optional_handle(&request.attachment_handle)?;
        request.expected_attachment_handle =
            canonical_optional_handle(&request.expected_attachment_handle)?;
        request.placement = Some(canonicalize_insert_placement(placement)?);
        Ok(Self {
            request,
            placement_values,
            reader,
            validated: None,
            sentinel_path: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn reader_mut(&mut self) -> &mut Reader {
        &mut self.reader
    }
}

pub(crate) fn validate_insert_xref_instance_step_two(
    request: &InsertXrefInstanceRequest,
) -> Result<(), XrefTransactionError> {
    let placement = request.placement.clone().unwrap_or(XrefInstancePlacement {
        owner_handle: None,
        owner_type: None,
        owner_name: None,
        layer_handle: None,
        layer_name: None,
        insertion_point: None,
        scale: None,
        rotation_degrees: None,
        normal: None,
        visibility: None,
        array: None,
    });
    validate_insert_placement_shape(&placement)
        .and_then(|_| validate_insert_placement_values(&placement).map(|_| ()))
}

impl<Reader> XrefMutationOperationCallback for InsertXrefInstanceOperation<Reader>
where
    Reader: XrefInstanceMutationReader,
{
    type Response = InsertXrefInstanceResponse;

    fn validate_locked(
        &mut self,
        context: &XrefLockedMutationContext<'_>,
    ) -> Result<(), XrefTransactionError> {
        let drawing = validate_context_path(&self.request.drawing_path, context.host_path)?;
        let attachments =
            validate_attachment_records(self.reader.list_attachments(context.host_path)?)?;
        let attachment = resolve_attachment(
            &attachments,
            self.request.attachment_handle.as_deref(),
            self.request.attachment_name.as_deref(),
        )?;
        if self
            .request
            .expected_attachment_handle
            .as_deref()
            .is_some_and(|expected| expected != attachment.handle)
        {
            return Err(domain_error(
                xrefs::xref_failure_code::EXPECTED_ATTACHMENT_HANDLE_MISMATCH,
                format!(
                    "expected attachment handle '{}' but locked target is '{}'",
                    self.request
                        .expected_attachment_handle
                        .as_deref()
                        .unwrap_or_default(),
                    attachment.handle
                ),
            ));
        }

        let environment = self.reader.read_environment(context.host_path)?;
        let placement = self
            .request
            .placement
            .as_ref()
            .expect("constructor always materializes placement defaults");
        let owner = resolve_owner(&environment, placement)?;
        if owner.handle == attachment.handle {
            return Err(domain_error(
                xrefs::xref_failure_code::UNSUPPORTED_XREF_OWNER,
                "target XREF definition cannot own one of its own instances",
            ));
        }
        let layer = resolve_layer(
            &environment,
            placement.layer_handle.as_deref(),
            placement.layer_name.as_deref(),
        )?;
        let (insertion_point, scale, rotation_degrees, normal, visibility, array) =
            self.placement_values;
        if would_create_recursive_ownership(&environment, &attachment.handle, &owner)? {
            return Err(domain_error(
                xrefs::xref_failure_code::RECURSIVE_BLOCK_REFERENCE,
                format!(
                    "inserting attachment '{}' into owner '{}' would create recursive ownership",
                    attachment.handle, owner.handle
                ),
            ));
        }

        let pre_instances = canonical_instances(
            self.reader
                .list_attachment_instances(context.host_path, &attachment.handle)?,
        )?;
        validate_attachment_count(&attachment, &pre_instances)?;
        let unit_factor = resolve_insert_unit_factor(
            &attachment.handle,
            &pre_instances,
            self.request.unit_assumptions.as_ref(),
            &environment.units,
        )?;
        unit_scaling_for(unit_factor, scale)?;
        let preservation = capture_instance_preservation(&mut self.reader, context)?;

        self.validated = Some(ValidatedInsert {
            drawing,
            pre_attachments: attachments,
            attachment: attachment.clone(),
            pre_instances,
            script: InsertScriptPlan {
                attachment_name: attachment.name,
                owner_handle: owner.handle,
                owner_type: owner.owner_type,
                owner_name: owner.name,
                layer_handle: layer.handle,
                layer_name: layer.name,
                insertion_point,
                scale,
                rotation_degrees,
                normal,
                visibility,
                array,
            },
            unit_factor,
            preservation,
        });
        Ok(())
    }

    fn execute(
        &mut self,
        engine: &mut dyn XrefMutationEngineBoundary,
        context: &XrefOperationContext<'_>,
    ) -> Result<Vec<PathBuf>, XrefTransactionError> {
        let validated = self.validated.as_ref().ok_or_else(|| {
            write_error("insert_xref_instance execute called before locked validation")
        })?;
        let (script, sentinel) = stage_script(
            engine,
            context,
            INSERT_SCRIPT_NAME,
            INSERT_SENTINEL_NAME,
            &XrefInstanceScriptPlan::Insert(validated.script.clone()),
        )?;
        self.sentinel_path = Some(sentinel.clone());
        Ok(vec![script, sentinel])
    }

    fn verify(
        &mut self,
        context: &XrefVerificationContext<'_>,
    ) -> Result<Self::Response, XrefTransactionError> {
        let validated = self.validated.as_ref().ok_or_else(|| {
            verification_error("insert_xref_instance verify called before locked validation")
        })?;
        let sentinel_path = self.sentinel_path.as_ref().ok_or_else(|| {
            verification_error("insert_xref_instance verify called before script staging")
        })?;
        let sentinel = read_success_sentinel(sentinel_path, "insert_xref_instance")?;
        let pre_handles = instance_handle_set(&validated.pre_instances);
        if pre_handles.contains(&sentinel.handle) {
            return Err(verification_error(format!(
                "insert_xref_instance reused existing handle '{}'",
                sentinel.handle
            )));
        }

        let mut instance = self
            .reader
            .get_instance(context.temporary_host, &sentinel.handle)?
            .ok_or_else(|| {
                verification_error(format!(
                    "inserted instance '{}' is absent from persisted reread",
                    sentinel.handle
                ))
            })
            .and_then(canonical_instance)?;
        let expected_scaling = unit_scaling_for(validated.unit_factor, validated.script.scale)?;
        match instance.unit_scaling {
            XrefUnitScaling::Unavailable => instance.unit_scaling = expected_scaling,
            actual if !scaling_matches(actual, expected_scaling) => {
                return Err(verification_error(
                    "inserted instance unit scaling disagrees with locked unit resolution",
                ))
            }
            _ => {}
        }

        let expected_kind = if validated.script.array.is_some() {
            XrefPlacementKind::RectangularArray
        } else {
            XrefPlacementKind::Single
        };
        if instance.attachment_handle != validated.attachment.handle
            || instance.attachment_name != validated.attachment.name
            || instance.owner_handle != validated.script.owner_handle
            || instance.owner_type != validated.script.owner_type
            || instance.owner_name != validated.script.owner_name
            || instance.layer_handle != validated.script.layer_handle
            || instance.layer_name != validated.script.layer_name
            || !point_matches(instance.insertion_point, validated.script.insertion_point)
            || !scale_matches(instance.scale, validated.script.scale)
            || !float_eq(instance.rotation_degrees, validated.script.rotation_degrees)
            || !vector_matches(instance.normal, validated.script.normal)
            || instance.visibility != validated.script.visibility
            || instance.placement_kind != expected_kind
            || instance.array != validated.script.array
        {
            return Err(verification_error(
                "persisted inserted instance does not match the validated owner/layer/placement",
            ));
        }

        let attachments =
            validate_attachment_records(self.reader.list_attachments(context.temporary_host)?)?;
        let attachment = attachment_by_handle(&attachments, &validated.attachment.handle)?;
        let after_instances = canonical_instances(
            self.reader
                .list_attachment_instances(context.temporary_host, &attachment.handle)?,
        )?;
        let expected_count = validated
            .attachment
            .instance_count
            .checked_add(1)
            .ok_or_else(|| verification_error("attachment instance_count overflow"))?;
        verify_attachment_count(&attachment, &after_instances, expected_count)?;
        verify_attachments_unchanged_except_count(
            &validated.pre_attachments,
            &attachments,
            &attachment.handle,
            expected_count,
        )?;
        let mut expected_handles = pre_handles;
        expected_handles.insert(instance.handle.clone());
        if instance_handle_set(&after_instances) != expected_handles {
            return Err(verification_error(
                "insert_xref_instance changed an existing instance or created more than one entity",
            ));
        }
        for before in &validated.pre_instances {
            let after = after_instances
                .iter()
                .find(|candidate| candidate.handle == before.handle)
                .expect("verified handle set contains every pre-insert instance");
            if !records_match(before, after) {
                return Err(verification_error(format!(
                    "insert_xref_instance changed existing instance '{}'",
                    before.handle
                )));
            }
        }
        verify_instance_preservation(
            &mut self.reader,
            XrefMutationOperation::InsertXrefInstance,
            &validated.preservation,
            &validated.attachment.handle,
            context,
        )?;

        Ok(InsertXrefInstanceResponse {
            status: InsertXrefInstanceStatus::Inserted,
            drawing: validated.drawing.clone(),
            instance,
        })
    }
}

#[derive(Debug, Clone)]
struct ValidatedUpdate {
    drawing: String,
    pre_attachments: Vec<XrefAttachmentRecord>,
    attachment: XrefAttachmentRecord,
    pre_instances: Vec<XrefInstanceRecord>,
    expected_instance: XrefInstanceRecord,
    script: UpdateScriptPlan,
    clip_fingerprint: Option<String>,
    preservation: XrefInstancePreservationState,
}

#[derive(Debug)]
pub(crate) struct UpdateXrefInstanceOperation<Reader> {
    request: UpdateXrefInstanceRequest,
    parsed_properties: ParsedUpdateProperties,
    reader: Reader,
    validated: Option<ValidatedUpdate>,
    sentinel_path: Option<PathBuf>,
}

impl<Reader> UpdateXrefInstanceOperation<Reader> {
    pub(crate) fn new(
        mut request: UpdateXrefInstanceRequest,
        reader: Reader,
    ) -> Result<Self, XrefTransactionError> {
        let mut parsed_properties =
            validate_context_free_update_values(parse_update_properties(&request)?)?;
        validate_absolute_drawing_path(&request.drawing_path)?;
        request.handle = canonical_handle(&request.handle)?;
        request.expected_attachment_handle =
            canonical_optional_handle(&request.expected_attachment_handle)?;
        request.expected_owner_handle = canonical_optional_handle(&request.expected_owner_handle)?;
        parsed_properties = canonicalize_update_property_handles(parsed_properties)?;
        Ok(Self {
            request,
            parsed_properties,
            reader,
            validated: None,
            sentinel_path: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn reader_mut(&mut self) -> &mut Reader {
        &mut self.reader
    }
}

pub(crate) fn validate_update_xref_instance_step_two(
    request: &UpdateXrefInstanceRequest,
) -> Result<(), XrefTransactionError> {
    parse_update_properties(request)
        .and_then(validate_context_free_update_values)
        .map(|_| ())
}

impl<Reader> XrefMutationOperationCallback for UpdateXrefInstanceOperation<Reader>
where
    Reader: XrefInstanceMutationReader,
{
    type Response = UpdateXrefInstanceResponse;

    fn validate_locked(
        &mut self,
        context: &XrefLockedMutationContext<'_>,
    ) -> Result<(), XrefTransactionError> {
        let drawing = validate_context_path(&self.request.drawing_path, context.host_path)?;
        let existing = self
            .reader
            .get_instance(context.host_path, &self.request.handle)?
            .ok_or_else(|| {
                domain_error(
                    xrefs::xref_failure_code::XREF_INSTANCE_NOT_FOUND,
                    format!("XREF instance '{}' was not found", self.request.handle),
                )
            })
            .and_then(canonical_instance)?;
        if self
            .request
            .expected_attachment_handle
            .as_deref()
            .is_some_and(|expected| expected != existing.attachment_handle)
        {
            return Err(domain_error(
                xrefs::xref_failure_code::EXPECTED_ATTACHMENT_HANDLE_MISMATCH,
                format!(
                    "expected attachment handle '{}' but instance parent is '{}'",
                    self.request
                        .expected_attachment_handle
                        .as_deref()
                        .unwrap_or_default(),
                    existing.attachment_handle
                ),
            ));
        }
        if self
            .request
            .expected_owner_handle
            .as_deref()
            .is_some_and(|expected| expected != existing.owner_handle)
        {
            return Err(domain_error(
                xrefs::xref_failure_code::EXPECTED_OWNER_HANDLE_MISMATCH,
                format!(
                    "expected owner handle '{}' but instance owner is '{}'",
                    self.request
                        .expected_owner_handle
                        .as_deref()
                        .unwrap_or_default(),
                    existing.owner_handle
                ),
            ));
        }

        let environment = self.reader.read_environment(context.host_path)?;
        owner_for_existing_instance(&environment, &existing)?;
        let source_layer = resolve_layer(
            &environment,
            Some(&existing.layer_handle),
            Some(&existing.layer_name),
        )?;
        let destination_layer = if self.parsed_properties.layer_handle.is_some()
            || self.parsed_properties.layer_name.is_some()
        {
            Some(resolve_layer(
                &environment,
                self.parsed_properties.layer_handle.as_deref(),
                self.parsed_properties.layer_name.as_deref(),
            )?)
        } else {
            None
        };
        if source_layer.locked {
            return Err(domain_error(
                xrefs::xref_failure_code::XREF_INSTANCE_LOCKED,
                format!(
                    "instance '{}' is on locked source layer '{}'",
                    existing.handle, source_layer.name
                ),
            ));
        }

        let properties = validate_update_values(self.parsed_properties.clone(), &existing)?;
        let unobservable_clip = XrefInstanceClipFacts::Unobservable;
        let clip_facts = environment
            .clips
            .get(&existing.handle)
            .unwrap_or(&unobservable_clip);
        let clip_fingerprint = validate_clip_policy(context, clip_facts, &existing.handle)?;

        let attachments =
            validate_attachment_records(self.reader.list_attachments(context.host_path)?)?;
        let attachment = attachments
            .iter()
            .find(|attachment| attachment.handle == existing.attachment_handle)
            .cloned()
            .ok_or_else(|| {
                domain_error(
                    xrefs::xref_failure_code::UNSUPPORTED_XREF_DATA,
                    "instance parent attachment is absent from locked portable reread",
                )
            })?;
        let pre_instances = canonical_instances(
            self.reader
                .list_attachment_instances(context.host_path, &attachment.handle)?,
        )?;
        validate_attachment_count(&attachment, &pre_instances)?;
        if !pre_instances
            .iter()
            .any(|instance| instance.handle == existing.handle)
        {
            return Err(domain_error(
                xrefs::xref_failure_code::UNSUPPORTED_XREF_DATA,
                "selected instance is absent from its parent attachment instance set",
            ));
        }
        let preservation = capture_instance_preservation(&mut self.reader, context)?;

        let mut expected = existing.clone();
        if let Some(point) = properties.insertion_point {
            expected.insertion_point = point;
        }
        if let Some(scale) = properties.scale {
            expected.scale = scale;
            if let Some(factor) = factor_from_scaling(existing.unit_scaling) {
                expected.unit_scaling = unit_scaling_for(factor, scale)?;
            }
        }
        if let Some(rotation) = properties.rotation_degrees {
            expected.rotation_degrees = rotation;
        }
        if let Some(normal) = properties.normal {
            expected.normal = normal;
        }
        if let Some(layer) = &destination_layer {
            expected.layer_handle = layer.handle.clone();
            expected.layer_name = layer.name.clone();
        }
        if let Some(visibility) = properties.visibility {
            expected.visibility = visibility;
        }
        if let Some(array) = properties.array {
            expected.array = Some(array);
        }
        expected = canonical_instance(expected)?;

        self.validated = Some(ValidatedUpdate {
            drawing,
            pre_attachments: attachments,
            attachment,
            pre_instances,
            expected_instance: expected,
            script: UpdateScriptPlan {
                handle: existing.handle,
                placement_kind: existing.placement_kind,
                properties,
                resolved_layer_name: destination_layer.map(|layer| layer.name),
            },
            clip_fingerprint,
            preservation,
        });
        Ok(())
    }

    fn execute(
        &mut self,
        engine: &mut dyn XrefMutationEngineBoundary,
        context: &XrefOperationContext<'_>,
    ) -> Result<Vec<PathBuf>, XrefTransactionError> {
        let validated = self.validated.as_ref().ok_or_else(|| {
            write_error("update_xref_instance execute called before locked validation")
        })?;
        let (script, sentinel) = stage_script(
            engine,
            context,
            UPDATE_SCRIPT_NAME,
            UPDATE_SENTINEL_NAME,
            &XrefInstanceScriptPlan::Update(validated.script.clone()),
        )?;
        self.sentinel_path = Some(sentinel.clone());
        Ok(vec![script, sentinel])
    }

    fn verify(
        &mut self,
        context: &XrefVerificationContext<'_>,
    ) -> Result<Self::Response, XrefTransactionError> {
        let validated = self.validated.as_ref().ok_or_else(|| {
            verification_error("update_xref_instance verify called before locked validation")
        })?;
        let sentinel_path = self.sentinel_path.as_ref().ok_or_else(|| {
            verification_error("update_xref_instance verify called before script staging")
        })?;
        let sentinel = read_success_sentinel(sentinel_path, "update_xref_instance")?;
        if sentinel.handle != validated.expected_instance.handle {
            return Err(verification_error(format!(
                "update_xref_instance sentinel handle '{}' does not match target '{}'",
                sentinel.handle, validated.expected_instance.handle
            )));
        }

        let mut instance = self
            .reader
            .get_instance(context.temporary_host, &sentinel.handle)?
            .ok_or_else(|| {
                verification_error(format!(
                    "updated instance '{}' is absent from persisted reread",
                    sentinel.handle
                ))
            })
            .and_then(canonical_instance)?;
        if matches!(instance.unit_scaling, XrefUnitScaling::Unavailable)
            && matches!(
                validated.expected_instance.unit_scaling,
                XrefUnitScaling::Available { .. }
            )
        {
            instance.unit_scaling = validated.expected_instance.unit_scaling;
        }
        if !records_match(&instance, &validated.expected_instance) {
            return Err(verification_error(
                "persisted updated instance does not equal the validated atomic replacement record",
            ));
        }

        let attachments =
            validate_attachment_records(self.reader.list_attachments(context.temporary_host)?)?;
        let attachment = attachment_by_handle(&attachments, &validated.attachment.handle)?;
        let after_instances = canonical_instances(
            self.reader
                .list_attachment_instances(context.temporary_host, &attachment.handle)?,
        )?;
        verify_attachment_count(
            &attachment,
            &after_instances,
            validated.attachment.instance_count,
        )?;
        verify_attachments_unchanged_except_count(
            &validated.pre_attachments,
            &attachments,
            &attachment.handle,
            validated.attachment.instance_count,
        )?;
        if instance_handle_set(&after_instances) != instance_handle_set(&validated.pre_instances) {
            return Err(verification_error(
                "update_xref_instance changed persisted instance identity or count",
            ));
        }
        for before in &validated.pre_instances {
            let after = after_instances
                .iter()
                .find(|candidate| candidate.handle == before.handle)
                .expect("equal handle sets guarantee a matching record");
            let expected = if before.handle == instance.handle {
                &validated.expected_instance
            } else {
                before
            };
            if !records_match(after, expected) {
                return Err(verification_error(format!(
                    "update_xref_instance changed unrelated instance '{}'",
                    before.handle
                )));
            }
        }

        if let Some(expected_fingerprint) = &validated.clip_fingerprint {
            let environment = self.reader.read_environment(context.temporary_host)?;
            match environment.clips.get(&instance.handle) {
                Some(XrefInstanceClipFacts::Present { fingerprint })
                    if fingerprint == expected_fingerprint => {}
                _ => {
                    return Err(verification_error(
                        "clip verifier evidence was not preserved across instance update",
                    ))
                }
            }
        }
        verify_instance_preservation(
            &mut self.reader,
            XrefMutationOperation::UpdateXrefInstance,
            &validated.preservation,
            &validated.attachment.handle,
            context,
        )?;

        Ok(UpdateXrefInstanceResponse {
            status: UpdateXrefInstanceStatus::Updated,
            drawing: validated.drawing.clone(),
            instance,
        })
    }
}

#[derive(Debug, Clone)]
struct ValidatedDelete {
    drawing: String,
    pre_attachments: Vec<XrefAttachmentRecord>,
    attachment: XrefAttachmentRecord,
    pre_instances: Vec<XrefInstanceRecord>,
    deleted_instance: XrefInstanceRecord,
    script: DeleteScriptPlan,
    had_verified_clip: bool,
    preservation: XrefInstancePreservationState,
}

#[derive(Debug)]
pub(crate) struct DeleteXrefInstanceOperation<Reader> {
    request: DeleteXrefInstanceRequest,
    reader: Reader,
    validated: Option<ValidatedDelete>,
    sentinel_path: Option<PathBuf>,
}

impl<Reader> DeleteXrefInstanceOperation<Reader> {
    pub(crate) fn new(
        mut request: DeleteXrefInstanceRequest,
        reader: Reader,
    ) -> Result<Self, XrefTransactionError> {
        validate_absolute_drawing_path(&request.drawing_path)?;
        request.handle = canonical_handle(&request.handle)?;
        request.expected_attachment_handle =
            canonical_optional_handle(&request.expected_attachment_handle)?;
        request.expected_owner_handle = canonical_optional_handle(&request.expected_owner_handle)?;
        Ok(Self {
            request,
            reader,
            validated: None,
            sentinel_path: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn reader(&self) -> &Reader {
        &self.reader
    }

    #[cfg(test)]
    pub(crate) fn reader_mut(&mut self) -> &mut Reader {
        &mut self.reader
    }
}

impl<Reader> XrefMutationOperationCallback for DeleteXrefInstanceOperation<Reader>
where
    Reader: XrefInstanceMutationReader,
{
    type Response = DeleteXrefInstanceResponse;

    fn validate_locked(
        &mut self,
        context: &XrefLockedMutationContext<'_>,
    ) -> Result<(), XrefTransactionError> {
        let drawing = validate_context_path(&self.request.drawing_path, context.host_path)?;
        let existing = self
            .reader
            .get_instance(context.host_path, &self.request.handle)?
            .ok_or_else(|| {
                domain_error(
                    xrefs::xref_failure_code::XREF_INSTANCE_NOT_FOUND,
                    format!("XREF instance '{}' was not found", self.request.handle),
                )
            })
            .and_then(canonical_instance)?;
        if self
            .request
            .expected_attachment_handle
            .as_deref()
            .is_some_and(|expected| expected != existing.attachment_handle)
        {
            return Err(domain_error(
                xrefs::xref_failure_code::EXPECTED_ATTACHMENT_HANDLE_MISMATCH,
                format!(
                    "expected attachment handle '{}' but instance parent is '{}'",
                    self.request
                        .expected_attachment_handle
                        .as_deref()
                        .unwrap_or_default(),
                    existing.attachment_handle
                ),
            ));
        }
        if self
            .request
            .expected_owner_handle
            .as_deref()
            .is_some_and(|expected| expected != existing.owner_handle)
        {
            return Err(domain_error(
                xrefs::xref_failure_code::EXPECTED_OWNER_HANDLE_MISMATCH,
                format!(
                    "expected owner handle '{}' but instance owner is '{}'",
                    self.request
                        .expected_owner_handle
                        .as_deref()
                        .unwrap_or_default(),
                    existing.owner_handle
                ),
            ));
        }

        let environment = self.reader.read_environment(context.host_path)?;
        owner_for_existing_instance(&environment, &existing)?;
        layer_for_existing_instance(&environment, &existing)?;
        let unobservable_clip = XrefInstanceClipFacts::Unobservable;
        let clip_facts = environment
            .clips
            .get(&existing.handle)
            .unwrap_or(&unobservable_clip);
        let had_verified_clip =
            validate_clip_policy(context, clip_facts, &existing.handle)?.is_some();

        let attachments =
            validate_attachment_records(self.reader.list_attachments(context.host_path)?)?;
        let attachment = attachments
            .iter()
            .find(|attachment| attachment.handle == existing.attachment_handle)
            .cloned()
            .ok_or_else(|| {
                domain_error(
                    xrefs::xref_failure_code::UNSUPPORTED_XREF_DATA,
                    "instance parent attachment is absent from locked portable reread",
                )
            })?;
        let pre_instances = canonical_instances(
            self.reader
                .list_attachment_instances(context.host_path, &attachment.handle)?,
        )?;
        validate_attachment_count(&attachment, &pre_instances)?;
        if !pre_instances
            .iter()
            .any(|instance| instance.handle == existing.handle)
        {
            return Err(domain_error(
                xrefs::xref_failure_code::UNSUPPORTED_XREF_DATA,
                "selected instance is absent from its parent attachment instance set",
            ));
        }
        let preservation = capture_instance_preservation(&mut self.reader, context)?;

        self.validated = Some(ValidatedDelete {
            drawing,
            pre_attachments: attachments,
            attachment,
            pre_instances,
            deleted_instance: existing.clone(),
            script: DeleteScriptPlan {
                handle: existing.handle,
                placement_kind: existing.placement_kind,
            },
            had_verified_clip,
            preservation,
        });
        Ok(())
    }

    fn execute(
        &mut self,
        engine: &mut dyn XrefMutationEngineBoundary,
        context: &XrefOperationContext<'_>,
    ) -> Result<Vec<PathBuf>, XrefTransactionError> {
        let validated = self.validated.as_ref().ok_or_else(|| {
            write_error("delete_xref_instance execute called before locked validation")
        })?;
        let (script, sentinel) = stage_script(
            engine,
            context,
            DELETE_SCRIPT_NAME,
            DELETE_SENTINEL_NAME,
            &XrefInstanceScriptPlan::Delete(validated.script.clone()),
        )?;
        self.sentinel_path = Some(sentinel.clone());
        Ok(vec![script, sentinel])
    }

    fn verify(
        &mut self,
        context: &XrefVerificationContext<'_>,
    ) -> Result<Self::Response, XrefTransactionError> {
        let validated = self.validated.as_ref().ok_or_else(|| {
            verification_error("delete_xref_instance verify called before locked validation")
        })?;
        let sentinel_path = self.sentinel_path.as_ref().ok_or_else(|| {
            verification_error("delete_xref_instance verify called before script staging")
        })?;
        let sentinel = read_success_sentinel(sentinel_path, "delete_xref_instance")?;
        if sentinel.handle != validated.deleted_instance.handle {
            return Err(verification_error(format!(
                "delete_xref_instance sentinel handle '{}' does not match target '{}'",
                sentinel.handle, validated.deleted_instance.handle
            )));
        }
        if self
            .reader
            .get_instance(context.temporary_host, &sentinel.handle)?
            .is_some()
        {
            return Err(verification_error(format!(
                "deleted instance '{}' remains in persisted output",
                sentinel.handle
            )));
        }

        let attachments =
            validate_attachment_records(self.reader.list_attachments(context.temporary_host)?)?;
        let attachment = attachment_by_handle(&attachments, &validated.attachment.handle)?;
        let after_instances = canonical_instances(
            self.reader
                .list_attachment_instances(context.temporary_host, &attachment.handle)?,
        )?;
        let expected_count = validated
            .attachment
            .instance_count
            .checked_sub(1)
            .ok_or_else(|| verification_error("pre-delete attachment count was already zero"))?;
        verify_attachment_count(&attachment, &after_instances, expected_count)?;
        verify_attachments_unchanged_except_count(
            &validated.pre_attachments,
            &attachments,
            &attachment.handle,
            expected_count,
        )?;
        let mut expected_handles = instance_handle_set(&validated.pre_instances);
        expected_handles.remove(&validated.deleted_instance.handle);
        if instance_handle_set(&after_instances) != expected_handles {
            return Err(verification_error(
                "delete_xref_instance removed or replaced an unrelated instance",
            ));
        }
        for before in &validated.pre_instances {
            if before.handle == validated.deleted_instance.handle {
                continue;
            }
            let after = after_instances
                .iter()
                .find(|candidate| candidate.handle == before.handle)
                .expect("equal handle sets guarantee a matching record");
            if !records_match(before, after) {
                return Err(verification_error(format!(
                    "delete_xref_instance changed unrelated instance '{}'",
                    before.handle
                )));
            }
        }

        if validated.had_verified_clip {
            let environment = self.reader.read_environment(context.temporary_host)?;
            if !matches!(
                environment.clips.get(&validated.deleted_instance.handle),
                None | Some(XrefInstanceClipFacts::Absent)
            ) {
                return Err(verification_error(
                    "clip verifier evidence remains after instance deletion",
                ));
            }
        }
        verify_instance_preservation(
            &mut self.reader,
            XrefMutationOperation::DeleteXrefInstance,
            &validated.preservation,
            &validated.attachment.handle,
            context,
        )?;

        Ok(DeleteXrefInstanceResponse {
            status: DeleteXrefInstanceStatus::Deleted,
            drawing: validated.drawing.clone(),
            instance: validated.deleted_instance.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    use crate::{
        certification::{
            XrefClipPolicy, XrefClipVerifierProfile, XrefDxfForm, XrefHostFormat,
            XrefMutationCapabilityRow, XrefMutationOperation, XrefPreservationVerifierProfile,
        },
        engine::AutocadEngineIdentity,
        ops::{
            xref_graph::XrefGraphSource,
            xref_mutation::{
                embedded_xref_mutation_admission, ProductionXrefFileSystem, XrefBoundaryError,
                XrefCapabilityQuery, XrefCertificationFailpoint, XrefFileObservation,
                XrefHostFormatFacts, XrefMutationAdmission, XrefMutationFileSystem,
                XrefSourceSnapshot,
            },
            xref_path::FilesystemIdentity,
            xrefs::{ReferenceType, XrefPathMode, XrefPointAvailability},
        },
    };

    #[derive(Debug, Clone, Copy, Eq, PartialEq)]
    enum FakePhase {
        Before,
        After,
    }

    #[derive(Debug, Clone)]
    struct FakeSnapshot {
        attachments: Vec<XrefAttachmentRecord>,
        instances: Vec<XrefInstanceRecord>,
        environment: XrefInstanceMutationEnvironment,
    }

    #[derive(Debug, Clone)]
    struct FakeReader {
        before: FakeSnapshot,
        after: FakeSnapshot,
        phase: FakePhase,
        preservation_calls: Vec<FakePreservationCall>,
        fail_preservation: bool,
    }

    #[derive(Debug, Clone, Eq, PartialEq)]
    struct FakePreservationCall {
        operation: XrefMutationOperation,
        profile_id: String,
        before_drawing: String,
        after_drawing: String,
        selected_attachment_handle: Option<String>,
        source_snapshot_count: usize,
    }

    impl FakeReader {
        fn snapshot(&self) -> &FakeSnapshot {
            match self.phase {
                FakePhase::Before => &self.before,
                FakePhase::After => &self.after,
            }
        }

        fn use_after(&mut self) {
            self.phase = FakePhase::After;
        }
    }

    impl XrefInstanceMutationReader for FakeReader {
        fn list_attachments(
            &mut self,
            _path: &Path,
        ) -> Result<Vec<XrefAttachmentRecord>, XrefTransactionError> {
            Ok(self.snapshot().attachments.clone())
        }

        fn get_instance(
            &mut self,
            _path: &Path,
            handle: &str,
        ) -> Result<Option<XrefInstanceRecord>, XrefTransactionError> {
            Ok(self
                .snapshot()
                .instances
                .iter()
                .find(|instance| instance.handle == handle)
                .cloned())
        }

        fn list_attachment_instances(
            &mut self,
            _path: &Path,
            attachment_handle: &str,
        ) -> Result<Vec<XrefInstanceRecord>, XrefTransactionError> {
            Ok(self
                .snapshot()
                .instances
                .iter()
                .filter(|instance| instance.attachment_handle == attachment_handle)
                .cloned()
                .collect())
        }

        fn read_environment(
            &mut self,
            _path: &Path,
        ) -> Result<XrefInstanceMutationEnvironment, XrefTransactionError> {
            Ok(self.snapshot().environment.clone())
        }

        fn read_preservation_snapshot(
            &mut self,
            path: &Path,
        ) -> Result<XrefAttachmentMutationSnapshot, XrefTransactionError> {
            Ok(preservation_snapshot(path, self.snapshot()))
        }

        fn verify_preservation(
            &mut self,
            verification: &XrefPreservationVerification<'_>,
        ) -> Result<(), XrefTransactionError> {
            self.preservation_calls.push(FakePreservationCall {
                operation: verification.operation,
                profile_id: verification.profile_id.to_string(),
                before_drawing: verification.before.drawing.clone(),
                after_drawing: verification.after.drawing.clone(),
                selected_attachment_handle: verification
                    .selected_attachment_handle
                    .map(str::to_string),
                source_snapshot_count: verification.source_snapshots.len(),
            });
            if self.fail_preservation {
                return Err(domain_error(
                    xrefs::xref_failure_code::UNSUPPORTED_XREF_DATA,
                    "injected whole-drawing preservation failure",
                ));
            }
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct FakeEngine {
        operation_scripts: Vec<PathBuf>,
    }

    impl XrefMutationEngineBoundary for FakeEngine {
        fn is_windows(&mut self) -> bool {
            true
        }

        fn detect_identity(&mut self) -> Result<AutocadEngineIdentity, XrefBoundaryError> {
            Ok(AutocadEngineIdentity {
                executable: PathBuf::from("/fake/accoreconsole.exe"),
                product: "autocad".to_string(),
                version: "2026".to_string(),
            })
        }

        fn launch(
            &mut self,
            _context: &crate::ops::xref_mutation::XrefEngineLaunchContext<'_>,
        ) -> Result<(), XrefBoundaryError> {
            Ok(())
        }

        fn execute_operation(&mut self, script: &Path) -> Result<(), XrefBoundaryError> {
            self.operation_scripts.push(script.to_path_buf());
            Ok(())
        }

        fn save(&mut self, _format: &XrefHostFormatFacts) -> Result<(), XrefBoundaryError> {
            Ok(())
        }

        fn auxiliary_artifacts(&self) -> Vec<PathBuf> {
            Vec::new()
        }

        fn stop(&mut self) -> Result<(), XrefBoundaryError> {
            Ok(())
        }

        fn certification_failpoint(
            &mut self,
            _failpoint: XrefCertificationFailpoint,
        ) -> Result<(), XrefBoundaryError> {
            Ok(())
        }
    }

    struct LockedFixture {
        path: PathBuf,
        observation: XrefFileObservation,
        format: XrefHostFormatFacts,
        admission: XrefMutationAdmission<'static>,
    }

    impl LockedFixture {
        fn new(path: &Path, operation: XrefMutationOperation) -> Self {
            let mut file_system = ProductionXrefFileSystem::default();
            let observation = file_system.observe_path(path).unwrap();
            let format = XrefHostFormatFacts {
                host_format: XrefHostFormat::Dwg,
                drawing_version: "AC1032".to_string(),
                dxf_form: XrefDxfForm::NotApplicable,
                code_page: None,
            };
            let admission = embedded_xref_mutation_admission(XrefCapabilityQuery {
                host_format: XrefHostFormat::Dwg,
                drawing_version: "AC1032",
                dxf_form: XrefDxfForm::NotApplicable,
                code_page: None,
                operation,
            })
            .unwrap();
            Self {
                path: path.to_path_buf(),
                observation,
                format,
                admission,
            }
        }

        fn context(&self) -> XrefLockedMutationContext<'_> {
            XrefLockedMutationContext {
                host_path: &self.path,
                host: &self.observation,
                format: &self.format,
                admission: &self.admission,
            }
        }
    }

    fn operation_context<'a>(
        host: &'a Path,
        staging: &'a Path,
        profile: &'a Path,
        sources: &'a [XrefSourceSnapshot],
    ) -> XrefOperationContext<'a> {
        XrefOperationContext {
            temporary_host: host,
            staging_directory: staging,
            profile_path: profile,
            source_snapshots: sources,
        }
    }

    fn verification_context<'a>(
        host: &'a Path,
        observation: &'a XrefFileObservation,
        sources: &'a [XrefSourceSnapshot],
    ) -> XrefVerificationContext<'a> {
        XrefVerificationContext {
            temporary_host: host,
            output: observation,
            source_snapshots: sources,
        }
    }

    fn attachment(count: u64) -> XrefAttachmentRecord {
        XrefAttachmentRecord {
            handle: "A".to_string(),
            name: "SITE".to_string(),
            saved_path: "refs/site.dwg".to_string(),
            path_mode: XrefPathMode::Relative,
            reference_type: ReferenceType::Attachment,
            load_state: xrefs::LoadState::Loaded,
            instance_count: count,
            definition_base_point: XrefPointAvailability::Available {
                point: XrefPoint3::ORIGIN,
            },
        }
    }

    fn available_scaling(scale: XrefScale3) -> XrefUnitScaling {
        XrefUnitScaling::Available {
            source_units: XrefUnitValue {
                value: InsertionUnit::Millimeters,
                basis: XrefUnitBasis::Drawing,
            },
            host_units: XrefUnitValue {
                value: InsertionUnit::Meters,
                basis: XrefUnitBasis::Drawing,
            },
            factor: 0.001,
            effective_scale: XrefScale3 {
                x: scale.x * 0.001,
                y: scale.y * 0.001,
                z: scale.z * 0.001,
            },
        }
    }

    fn instance(handle: &str) -> XrefInstanceRecord {
        let scale = XrefScale3::IDENTITY;
        XrefInstanceRecord {
            handle: handle.to_string(),
            attachment_handle: "A".to_string(),
            attachment_name: "SITE".to_string(),
            owner_handle: "1F".to_string(),
            owner_type: xrefs::XrefOwnerType::ModelSpace,
            owner_name: "Model".to_string(),
            layer_handle: "20".to_string(),
            layer_name: "0".to_string(),
            insertion_point: XrefPoint3::ORIGIN,
            scale,
            rotation_degrees: 0.0,
            normal: XrefVector3::WORLD_Z,
            visibility: XrefVisibility::Visible,
            placement_kind: XrefPlacementKind::Single,
            array: None,
            unit_scaling: available_scaling(scale),
        }
    }

    fn minsert_instance(handle: &str, rows: u32, columns: u32) -> XrefInstanceRecord {
        XrefInstanceRecord {
            placement_kind: XrefPlacementKind::RectangularArray,
            array: Some(XrefRectangularArray {
                rows,
                columns,
                row_spacing: 10.0,
                column_spacing: 20.0,
            }),
            ..instance(handle)
        }
    }

    fn environment() -> XrefInstanceMutationEnvironment {
        XrefInstanceMutationEnvironment {
            owners: vec![
                XrefInstanceOwnerFacts {
                    handle: "1F".to_string(),
                    owner_type: xrefs::XrefOwnerType::ModelSpace,
                    name: "Model".to_string(),
                    write_state: XrefOwnerWriteState::Writable,
                },
                XrefInstanceOwnerFacts {
                    handle: "2F".to_string(),
                    owner_type: xrefs::XrefOwnerType::PaperSpace,
                    name: "Sheet A".to_string(),
                    write_state: XrefOwnerWriteState::Writable,
                },
                XrefInstanceOwnerFacts {
                    handle: "3F".to_string(),
                    owner_type: xrefs::XrefOwnerType::BlockDefinition,
                    name: "DETAIL".to_string(),
                    write_state: XrefOwnerWriteState::Writable,
                },
            ],
            layers: vec![
                XrefInstanceLayerFacts {
                    handle: "20".to_string(),
                    name: "0".to_string(),
                    ownership: XrefLayerOwnership::HostOwned,
                    locked: false,
                },
                XrefInstanceLayerFacts {
                    handle: "21".to_string(),
                    name: "LOCKED".to_string(),
                    ownership: XrefLayerOwnership::HostOwned,
                    locked: true,
                },
                XrefInstanceLayerFacts {
                    handle: "22".to_string(),
                    name: "SITE|GRID".to_string(),
                    ownership: XrefLayerOwnership::XrefDependent,
                    locked: false,
                },
            ],
            block_references: BTreeMap::new(),
            block_reference_graph_complete: true,
            clips: BTreeMap::from([("10".to_string(), XrefInstanceClipFacts::Absent)]),
            units: XrefInstanceUnitFacts {
                host_units: PersistedInsertionUnits::Known {
                    value: InsertionUnit::Meters,
                },
                attachment_units: BTreeMap::from([(
                    "A".to_string(),
                    PersistedInsertionUnits::Known {
                        value: InsertionUnit::Millimeters,
                    },
                )]),
                host_unobservable_uses_profile_default: false,
                source_unobservable_uses_profile_default: BTreeSet::new(),
                supported_profile_default_units: vec![
                    InsertionUnit::Millimeters,
                    InsertionUnit::Meters,
                    InsertionUnit::Feet,
                ],
            },
        }
    }

    fn snapshot(instances: Vec<XrefInstanceRecord>) -> FakeSnapshot {
        let mut environment = environment();
        for instance in &instances {
            environment
                .clips
                .entry(instance.handle.clone())
                .or_insert(XrefInstanceClipFacts::Absent);
        }
        FakeSnapshot {
            attachments: vec![attachment(instances.len() as u64)],
            instances,
            environment,
        }
    }

    fn preservation_snapshot(
        path: &Path,
        snapshot: &FakeSnapshot,
    ) -> XrefAttachmentMutationSnapshot {
        let drawing = path.to_string_lossy().into_owned();
        let graph_source = XrefGraphSource::from_filesystem_canonical_path(
            &drawing,
            FilesystemIdentity::opaque(drawing.as_bytes().to_vec()).unwrap(),
            snapshot.attachments.clone(),
        )
        .unwrap();
        XrefAttachmentMutationSnapshot {
            drawing,
            graph_source,
            attachments: snapshot.attachments.clone(),
            instances: snapshot.instances.clone(),
            block_definitions_complete: true,
            block_definitions: Vec::new(),
            owners_complete: true,
            owners: Vec::new(),
            layers_complete: true,
            layers: Vec::new(),
            attachment_preflight: Vec::new(),
            reconciliation_layers_complete: true,
            reconciliation_layers: Vec::new(),
            saved_visretain: 1,
            saved_xrefoverride: 0,
        }
    }

    fn reader(before: Vec<XrefInstanceRecord>, after: Vec<XrefInstanceRecord>) -> FakeReader {
        FakeReader {
            before: snapshot(before),
            after: snapshot(after),
            phase: FakePhase::Before,
            preservation_calls: Vec::new(),
            fail_preservation: false,
        }
    }

    fn insert_request(path: &Path) -> InsertXrefInstanceRequest {
        InsertXrefInstanceRequest {
            drawing_path: path.to_string_lossy().into_owned(),
            attachment_handle: Some("0x0a".to_string()),
            attachment_name: Some("site".to_string()),
            expected_attachment_handle: Some("A".to_string()),
            placement: None,
            unit_assumptions: None,
        }
    }

    fn update_request(
        path: &Path,
        properties: BTreeMap<String, serde_json::Value>,
    ) -> UpdateXrefInstanceRequest {
        UpdateXrefInstanceRequest {
            drawing_path: path.to_string_lossy().into_owned(),
            handle: "0x10".to_string(),
            expected_attachment_handle: Some("0xA".to_string()),
            expected_owner_handle: Some("0x1f".to_string()),
            properties,
        }
    }

    fn delete_request(path: &Path) -> DeleteXrefInstanceRequest {
        DeleteXrefInstanceRequest {
            drawing_path: path.to_string_lossy().into_owned(),
            handle: "0x10".to_string(),
            expected_attachment_handle: Some("A".to_string()),
            expected_owner_handle: Some("1F".to_string()),
        }
    }

    fn error_code(error: XrefTransactionError) -> String {
        error.code.as_str().to_string()
    }

    fn assert_preservation_call(
        reader: &FakeReader,
        operation: XrefMutationOperation,
        drawing: &Path,
    ) {
        let drawing = drawing.to_string_lossy().into_owned();
        assert_eq!(
            reader.preservation_calls,
            vec![FakePreservationCall {
                operation,
                profile_id: "xref-preservation-v1".to_string(),
                before_drawing: drawing.clone(),
                after_drawing: drawing,
                selected_attachment_handle: Some("A".to_string()),
                source_snapshot_count: 0,
            }]
        );
    }

    fn write_host(path: &Path) {
        fs::write(path, b"fake-host").unwrap();
    }

    fn write_sentinel(path: &Path, operation: &str, handle: &str) {
        fs::write(
            path,
            serde_json::to_vec(&XrefInstanceMutationSentinel {
                schema_version: 1,
                operation: operation.to_string(),
                status: "ok".to_string(),
                handle: handle.to_string(),
            })
            .unwrap(),
        )
        .unwrap();
    }

    fn assert_balanced_lisp(source: &str) {
        let mut depth = 0_i32;
        let mut in_string = false;
        let mut escaped = false;
        let mut comment = false;
        for character in source.chars() {
            if character == '\n' {
                comment = false;
                continue;
            }
            if comment {
                continue;
            }
            if in_string {
                if escaped {
                    escaped = false;
                } else if character == '\\' {
                    escaped = true;
                } else if character == '"' {
                    in_string = false;
                }
                continue;
            }
            match character {
                ';' => comment = true,
                '"' => in_string = true,
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    assert!(depth >= 0, "script has an unmatched closing parenthesis");
                }
                _ => {}
            }
        }
        assert!(!in_string, "script has an unterminated string");
        assert_eq!(depth, 0, "script has unclosed parentheses");
    }

    fn placement() -> XrefInstancePlacement {
        XrefInstancePlacement {
            owner_handle: None,
            owner_type: None,
            owner_name: None,
            layer_handle: None,
            layer_name: None,
            insertion_point: None,
            scale: None,
            rotation_degrees: None,
            normal: None,
            visibility: None,
            array: None,
        }
    }

    #[test]
    fn owner_selector_union_defaults_agreement_and_write_states_are_exact() {
        let environment = environment();
        assert_eq!(
            resolve_owner(&environment, &placement()).unwrap().handle,
            "1F"
        );

        let mut by_handle = placement();
        by_handle.owner_handle = Some("2F".to_string());
        assert_eq!(
            resolve_owner(&environment, &by_handle).unwrap().name,
            "Sheet A"
        );

        let mut semantic = placement();
        semantic.owner_type = Some(xrefs::XrefOwnerType::BlockDefinition);
        semantic.owner_name = Some("detail".to_string());
        assert_eq!(resolve_owner(&environment, &semantic).unwrap().handle, "3F");

        semantic.owner_handle = Some("3F".to_string());
        assert_eq!(resolve_owner(&environment, &semantic).unwrap().handle, "3F");
        semantic.owner_handle = Some("2F".to_string());
        assert_eq!(
            error_code(resolve_owner(&environment, &semantic).unwrap_err()),
            xrefs::xref_failure_code::CONTRADICTORY_IDENTITY
        );

        let mut invalid = placement();
        invalid.owner_type = Some(xrefs::XrefOwnerType::ModelSpace);
        assert_eq!(
            error_code(canonicalize_insert_placement(invalid).unwrap_err()),
            xrefs::xref_failure_code::INVALID_XREF_OWNER
        );

        for state in [
            XrefOwnerWriteState::XrefDefinition,
            XrefOwnerWriteState::XrefDependent,
            XrefOwnerWriteState::Anonymous,
            XrefOwnerWriteState::Dynamic,
            XrefOwnerWriteState::AutocadManaged,
            XrefOwnerWriteState::ReadOnly,
            XrefOwnerWriteState::Unsupported,
        ] {
            let mut unsupported = environment.clone();
            unsupported.owners[0].write_state = state;
            assert_eq!(
                error_code(resolve_owner(&unsupported, &placement()).unwrap_err()),
                xrefs::xref_failure_code::UNSUPPORTED_XREF_OWNER,
                "state={state:?}"
            );
        }
    }

    #[test]
    fn layer_selectors_default_agree_and_distinguish_host_ownership_from_locking() {
        let environment = environment();
        let default = resolve_layer(&environment, None, None).unwrap();
        assert_eq!(default.handle, "20");
        assert!(!default.locked);

        let locked = resolve_layer(&environment, Some("21"), Some("locked")).unwrap();
        assert!(locked.locked, "locked destination layers remain selectable");

        assert_eq!(
            error_code(resolve_layer(&environment, Some("20"), Some("LOCKED")).unwrap_err()),
            xrefs::xref_failure_code::CONTRADICTORY_IDENTITY
        );
        assert_eq!(
            error_code(resolve_layer(&environment, None, Some("SITE|GRID")).unwrap_err()),
            xrefs::xref_failure_code::LAYER_NOT_HOST_OWNED
        );
        let mut unsupported = environment.clone();
        unsupported.layers[0].ownership = XrefLayerOwnership::Unsupported;
        assert_eq!(
            error_code(resolve_layer(&unsupported, None, None).unwrap_err()),
            xrefs::xref_failure_code::LAYER_NOT_HOST_OWNED
        );
        assert_eq!(
            error_code(resolve_layer(&environment, Some("99"), None).unwrap_err()),
            xrefs::xref_failure_code::LAYER_NOT_FOUND
        );
    }

    #[test]
    fn block_owner_cycle_detection_is_transitive_and_fails_closed() {
        let mut environment = environment();
        let owner = environment.owners[2].clone();
        environment
            .block_references
            .insert("A".to_string(), vec!["30".to_string()]);
        environment
            .block_references
            .insert("30".to_string(), vec!["3F".to_string()]);
        assert!(would_create_recursive_ownership(&environment, "A", &owner).unwrap());

        environment.block_references.clear();
        assert!(!would_create_recursive_ownership(&environment, "A", &owner).unwrap());
        environment.block_reference_graph_complete = false;
        assert_eq!(
            error_code(would_create_recursive_ownership(&environment, "A", &owner).unwrap_err()),
            xrefs::xref_failure_code::UNSUPPORTED_XREF_DATA
        );
    }

    #[test]
    fn placement_validation_canonicalizes_ocs_rotation_scale_normal_visibility_and_arrays() {
        let mut value = placement();
        value.insertion_point = Some(XrefPoint3 {
            x: 4.0,
            y: 5.0,
            z: 6.0,
        });
        value.scale = Some(XrefScale3 {
            x: -2.0,
            y: 3.0,
            z: 4.0,
        });
        value.rotation_degrees = Some(720.0);
        value.normal = Some(XrefVector3 {
            x: 0.0,
            y: 1.0,
            z: 0.0,
        });
        value.visibility = Some(XrefVisibility::Hidden);
        value.array = Some(XrefRectangularArray {
            rows: 1,
            columns: 1,
            row_spacing: 0.0,
            column_spacing: 0.0,
        });
        let (_, scale, rotation, normal, visibility, array) =
            validate_insert_placement_values(&value).unwrap();
        assert_eq!(scale.x, -2.0);
        assert_eq!(rotation, 0.0);
        assert_eq!(normal.y, 1.0);
        assert_eq!(visibility, XrefVisibility::Hidden);
        assert_eq!(array.unwrap().rows, 1, "1x1 remains an MINSERT request");

        value.scale = Some(XrefScale3 {
            x: 0.0,
            y: 1.0,
            z: 1.0,
        });
        assert_eq!(
            error_code(validate_insert_placement_values(&value).unwrap_err()),
            xrefs::xref_failure_code::INVALID_XREF_SCALE
        );
        value.scale = None;
        value.normal = Some(XrefVector3 {
            x: 0.0,
            y: 0.0,
            z: 2.0,
        });
        assert_eq!(
            error_code(validate_insert_placement_values(&value).unwrap_err()),
            xrefs::xref_failure_code::INVALID_XREF_NORMAL
        );
        value.normal = None;
        value.insertion_point = Some(XrefPoint3 {
            x: f64::NAN,
            y: 0.0,
            z: 0.0,
        });
        assert_eq!(
            error_code(validate_insert_placement_values(&value).unwrap_err()),
            xrefs::xref_failure_code::INVALID_XREF_PLACEMENT
        );
    }

    #[test]
    fn context_free_placement_values_precede_path_and_handle_syntax() {
        let mut insert = insert_request(Path::new("/host.dwg"));
        insert.placement = Some(XrefInstancePlacement {
            owner_handle: Some("not-hex".to_string()),
            scale: Some(XrefScale3 {
                x: 0.0,
                y: 1.0,
                z: 1.0,
            }),
            ..placement()
        });
        assert_eq!(
            error_code(
                InsertXrefInstanceOperation::new(insert, reader(Vec::new(), Vec::new()))
                    .unwrap_err()
            ),
            xrefs::xref_failure_code::INVALID_XREF_SCALE
        );

        let mut relative = insert_request(Path::new("host.dwg"));
        relative.placement = Some(XrefInstancePlacement {
            owner_handle: Some("not-hex".to_string()),
            ..placement()
        });
        assert_eq!(
            error_code(
                InsertXrefInstanceOperation::new(relative, reader(Vec::new(), Vec::new()))
                    .unwrap_err()
            ),
            xrefs::xref_failure_code::DRAWING_UNREADABLE
        );

        let update = update_request(
            Path::new("/host.dwg"),
            BTreeMap::from([
                ("layer_handle".to_string(), serde_json::json!("not-hex")),
                (
                    "scale".to_string(),
                    serde_json::json!({"x": 0.0, "y": 1.0, "z": 1.0}),
                ),
            ]),
        );
        assert_eq!(
            error_code(
                UpdateXrefInstanceOperation::new(update, reader(Vec::new(), Vec::new()))
                    .unwrap_err()
            ),
            xrefs::xref_failure_code::INVALID_XREF_SCALE
        );
    }

    #[test]
    fn update_property_classifier_shapes_and_array_replacement_are_closed() {
        let path = Path::new("/host.dwg");
        let empty = update_request(path, BTreeMap::new());
        assert_eq!(
            error_code(parse_update_properties(&empty).unwrap_err()),
            xrefs::xref_failure_code::EMPTY_XREF_UPDATE
        );

        let unknown = update_request(
            path,
            BTreeMap::from([("mystery".to_string(), serde_json::json!(1))]),
        );
        assert_eq!(
            error_code(parse_update_properties(&unknown).unwrap_err()),
            xrefs::xref_failure_code::INVALID_XREF_PROPERTY
        );
        let unsupported = update_request(
            path,
            BTreeMap::from([("owner_handle".to_string(), serde_json::json!("1F"))]),
        );
        assert_eq!(
            error_code(parse_update_properties(&unsupported).unwrap_err()),
            xrefs::xref_failure_code::UNSUPPORTED_XREF_PROPERTY
        );
        let numeric_handle = update_request(
            path,
            BTreeMap::from([("layer_handle".to_string(), serde_json::json!(20))]),
        );
        assert_eq!(
            error_code(parse_update_properties(&numeric_handle).unwrap_err()),
            xrefs::xref_failure_code::INVALID_PARAMETERS
        );

        let replacement = update_request(
            path,
            BTreeMap::from([(
                "array".to_string(),
                serde_json::json!({
                    "rows": 1,
                    "columns": 1,
                    "row_spacing": 3.0,
                    "column_spacing": 4.0
                }),
            )]),
        );
        let parsed =
            validate_context_free_update_values(parse_update_properties(&replacement).unwrap())
                .unwrap();
        assert_eq!(
            error_code(validate_update_values(parsed.clone(), &instance("10")).unwrap_err()),
            xrefs::xref_failure_code::INVALID_XREF_PLACEMENT
        );
        let validated = validate_update_values(parsed, &minsert_instance("10", 1, 1)).unwrap();
        assert_eq!(validated.array.unwrap().rows, 1);
    }

    #[test]
    fn unit_factor_order_prefers_survivors_then_persisted_then_conditional_assumptions() {
        let facts = environment().units;
        let surviving = resolve_insert_unit_factor("A", &[instance("10")], None, &facts).unwrap();
        assert_eq!(surviving.source_units.basis, XrefUnitBasis::Drawing);
        assert!(float_eq(surviving.factor, 0.001));

        let persisted = resolve_insert_unit_factor("A", &[], None, &facts).unwrap();
        assert!(same_factor(surviving, persisted));

        let mut conflicting = instance("11");
        conflicting.unit_scaling = XrefUnitScaling::Available {
            source_units: XrefUnitValue {
                value: InsertionUnit::Feet,
                basis: XrefUnitBasis::Request,
            },
            host_units: XrefUnitValue {
                value: InsertionUnit::Meters,
                basis: XrefUnitBasis::Drawing,
            },
            factor: 0.3048,
            effective_scale: XrefScale3 {
                x: 0.3048,
                y: 0.3048,
                z: 0.3048,
            },
        };
        assert_eq!(
            error_code(
                resolve_insert_unit_factor("A", &[instance("10"), conflicting], None, &facts)
                    .unwrap_err()
            ),
            xrefs::xref_failure_code::UNSUPPORTED_XREF_DATA
        );

        let mut assumable = facts.clone();
        assumable.host_units = PersistedInsertionUnits::Unitless;
        assumable
            .attachment_units
            .insert("A".to_string(), PersistedInsertionUnits::Unitless);
        assert_eq!(
            error_code(resolve_insert_unit_factor("A", &[], None, &assumable).unwrap_err()),
            xrefs::xref_failure_code::AMBIGUOUS_INSERTION_UNITS
        );
        let assumptions = XrefUnitAssumptions {
            source_units: Some(InsertionUnit::Millimeters),
            host_units: Some(InsertionUnit::Meters),
        };
        let requested =
            resolve_insert_unit_factor("A", &[], Some(&assumptions), &assumable).unwrap();
        assert_eq!(requested.source_units.basis, XrefUnitBasis::Request);
        assert_eq!(requested.host_units.basis, XrefUnitBasis::Request);
        assert!(float_eq(requested.factor, 0.001));
        assert_eq!(
            xref_instance_unit_profile_defaults(Some(&assumptions)),
            BTreeMap::from([
                ("host_units".to_string(), "meters".to_string()),
                ("source_units".to_string(), "millimeters".to_string()),
            ])
        );

        let mut request_basis_instance = instance("12");
        request_basis_instance.unit_scaling = XrefUnitScaling::Available {
            source_units: XrefUnitValue {
                value: InsertionUnit::Millimeters,
                basis: XrefUnitBasis::Request,
            },
            host_units: XrefUnitValue {
                value: InsertionUnit::Meters,
                basis: XrefUnitBasis::Request,
            },
            factor: 0.001,
            effective_scale: XrefScale3 {
                x: 0.001,
                y: 0.001,
                z: 0.001,
            },
        };
        assert_eq!(
            error_code(
                resolve_insert_unit_factor("A", &[request_basis_instance.clone()], None, &facts)
                    .unwrap_err()
            ),
            xrefs::xref_failure_code::AMBIGUOUS_INSERTION_UNITS
        );
        assert!(same_factor(
            resolve_insert_unit_factor("A", &[request_basis_instance], Some(&assumptions), &facts)
                .unwrap(),
            requested
        ));
    }

    #[test]
    fn unit_assumptions_cannot_override_proven_or_unknown_units() {
        let facts = environment().units;
        let assumptions = XrefUnitAssumptions {
            source_units: Some(InsertionUnit::Feet),
            host_units: None,
        };
        assert_eq!(
            error_code(
                resolve_insert_unit_factor("A", &[], Some(&assumptions), &facts).unwrap_err()
            ),
            xrefs::xref_failure_code::INVALID_UNIT_ASSUMPTIONS
        );

        let mut unknown = facts.clone();
        unknown.attachment_units.insert(
            "A".to_string(),
            PersistedInsertionUnits::UnknownCode { code: 999 },
        );
        assert_eq!(
            error_code(resolve_insert_unit_factor("A", &[], None, &unknown).unwrap_err()),
            xrefs::xref_failure_code::UNSUPPORTED_INSERTION_UNITS
        );

        let mut unobservable = facts;
        unobservable.host_units = PersistedInsertionUnits::Unobservable;
        assert_eq!(
            error_code(resolve_insert_unit_factor("A", &[], None, &unobservable).unwrap_err()),
            xrefs::xref_failure_code::UNSUPPORTED_INSERTION_UNITS
        );
    }

    #[test]
    fn scripts_are_deterministic_owner_coordinate_explicit_and_ambient_state_free() {
        assert_eq!(lisp_number(1e-300), "1e-300");
        assert_eq!(lisp_number(-0.0), "0.0");
        let insert = XrefInstanceScriptPlan::Insert(InsertScriptPlan {
            attachment_name: "SITE".to_string(),
            owner_handle: "3F".to_string(),
            owner_type: xrefs::XrefOwnerType::BlockDefinition,
            owner_name: "DETAIL".to_string(),
            layer_handle: "21".to_string(),
            layer_name: "LOCKED".to_string(),
            insertion_point: XrefPoint3 {
                x: 1.0,
                y: 2.0,
                z: 3.0,
            },
            scale: XrefScale3 {
                x: -1.0,
                y: 2.0,
                z: 3.0,
            },
            rotation_degrees: 45.0,
            normal: XrefVector3 {
                x: 0.0,
                y: 1.0,
                z: 0.0,
            },
            visibility: XrefVisibility::Hidden,
            array: Some(XrefRectangularArray {
                rows: 1,
                columns: 1,
                row_spacing: 0.0,
                column_spacing: 0.0,
            }),
        });
        let path = Path::new("/stage/result.json");
        let first = render_xref_instance_script(&insert, path);
        let second = render_xref_instance_script(&insert, path);
        assert_eq!(first, second);
        assert_balanced_lisp(&first);
        for required in [
            "(acmcp-object-by-handle \"3F\")",
            "vla-AddMInsertBlock",
            "AcDbMInsertBlock",
            "(vla-put-Layer object \"LOCKED\")",
            "(vla-put-XScaleFactor object -1.0)",
            "(vla-put-Normal object",
            "(vla-put-Visible object :vlax-false)",
            "AUTOCAD_MCP_XREF_RESULT",
            "\\\"schema_version\\\":1",
        ] {
            assert!(first.contains(required), "missing {required}");
        }
        for forbidden in [
            "(command",
            "(ssget",
            "(trans",
            "CLAYER",
            "CTAB",
            "ActiveLayout",
            "UCS",
            "ModelSpace",
            "PaperSpace",
        ] {
            assert!(!first.contains(forbidden), "ambient dependency {forbidden}");
        }

        let update = render_xref_instance_script(
            &XrefInstanceScriptPlan::Update(UpdateScriptPlan {
                handle: "10".to_string(),
                placement_kind: XrefPlacementKind::RectangularArray,
                properties: ParsedUpdateProperties {
                    array: Some(XrefRectangularArray {
                        rows: 2,
                        columns: 3,
                        row_spacing: 4.0,
                        column_spacing: 5.0,
                    }),
                    visibility: Some(XrefVisibility::Visible),
                    ..ParsedUpdateProperties::default()
                },
                resolved_layer_name: None,
            }),
            path,
        );
        assert!(update.contains("vla-put-Rows object 2"));
        assert!(update.contains("vla-put-Columns object 3"));
        assert!(update.contains("AcDbMInsertBlock"));
        assert_balanced_lisp(&update);

        let delete = render_xref_instance_script(
            &XrefInstanceScriptPlan::Delete(DeleteScriptPlan {
                handle: "10".to_string(),
                placement_kind: XrefPlacementKind::Single,
            }),
            path,
        );
        assert!(delete.contains("vla-Delete object"));
        assert!(delete.contains("AcDbBlockReference"));
        assert_balanced_lisp(&delete);
    }

    #[test]
    fn sentinel_parser_is_closed_and_requires_matching_success_and_canonical_handle() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("result.json");
        write_sentinel(&path, "insert_xref_instance", "2A");
        assert_eq!(
            read_success_sentinel(&path, "insert_xref_instance")
                .unwrap()
                .handle,
            "2A"
        );

        fs::write(
            &path,
            br#"{"schema_version":1,"operation":"insert_xref_instance","status":"error","handle":""}"#,
        )
        .unwrap();
        assert_eq!(
            read_success_sentinel(&path, "insert_xref_instance")
                .unwrap_err()
                .code,
            XrefTransactionErrorCode::VerificationFailed
        );
        fs::write(
            &path,
            br#"{"schema_version":1,"operation":"insert_xref_instance","status":"ok","handle":"2a","extra":true}"#,
        )
        .unwrap();
        assert_eq!(
            read_success_sentinel(&path, "insert_xref_instance")
                .unwrap_err()
                .code,
            XrefTransactionErrorCode::VerificationFailed
        );
    }

    #[test]
    fn insert_callback_stages_script_and_returns_the_exact_persisted_reread() {
        let temporary = tempfile::tempdir().unwrap();
        let host = temporary.path().join("host.dwg");
        let staging = temporary.path().join("stage");
        fs::create_dir(&staging).unwrap();
        write_host(&host);

        let inserted = instance("30");
        let fake_reader = reader(Vec::new(), vec![inserted.clone()]);
        let mut operation =
            InsertXrefInstanceOperation::new(insert_request(&host), fake_reader).unwrap();
        let locked = LockedFixture::new(&host, XrefMutationOperation::InsertXrefInstance);
        operation.validate_locked(&locked.context()).unwrap();
        let mut engine = FakeEngine::default();
        let sources = Vec::new();
        let profile = staging.join("profile.arg");
        let artifacts = operation
            .execute(
                &mut engine,
                &operation_context(&host, &staging, &profile, &sources),
            )
            .unwrap();
        assert_eq!(artifacts.len(), 2);
        assert_eq!(
            engine.operation_scripts,
            vec![staging.join(INSERT_SCRIPT_NAME)]
        );
        assert!(fs::read_to_string(&artifacts[0])
            .unwrap()
            .contains("insert_xref_instance"));
        write_sentinel(
            &staging.join(INSERT_SENTINEL_NAME),
            "insert_xref_instance",
            "30",
        );
        operation.reader_mut().use_after();

        let mut file_system = ProductionXrefFileSystem::default();
        let output = file_system.observe_path(&host).unwrap();
        let response = operation
            .verify(&verification_context(&host, &output, &sources))
            .unwrap();
        assert_eq!(response.status, InsertXrefInstanceStatus::Inserted);
        assert_eq!(response.drawing, host.to_string_lossy());
        assert_eq!(response.instance, inserted);
        assert_preservation_call(
            operation.reader_mut(),
            XrefMutationOperation::InsertXrefInstance,
            &host,
        );
    }

    #[test]
    fn whole_drawing_preservation_failure_blocks_instance_success() {
        let temporary = tempfile::tempdir().unwrap();
        let host = temporary.path().join("host.dwg");
        let staging = temporary.path().join("stage");
        fs::create_dir(&staging).unwrap();
        write_host(&host);

        let mut fake_reader = reader(Vec::new(), vec![instance("30")]);
        fake_reader.fail_preservation = true;
        let mut operation =
            InsertXrefInstanceOperation::new(insert_request(&host), fake_reader).unwrap();
        let locked = LockedFixture::new(&host, XrefMutationOperation::InsertXrefInstance);
        operation.validate_locked(&locked.context()).unwrap();
        let sources = Vec::new();
        operation
            .execute(
                &mut FakeEngine::default(),
                &operation_context(&host, &staging, &staging.join("profile.arg"), &sources),
            )
            .unwrap();
        write_sentinel(
            &staging.join(INSERT_SENTINEL_NAME),
            "insert_xref_instance",
            "30",
        );
        operation.reader_mut().use_after();
        let mut file_system = ProductionXrefFileSystem::default();
        let output = file_system.observe_path(&host).unwrap();

        let error = operation
            .verify(&verification_context(&host, &output, &sources))
            .unwrap_err();
        assert_eq!(error.code, XrefTransactionErrorCode::VerificationFailed);
        assert!(error
            .detail
            .contains("injected whole-drawing preservation failure"));
        assert_preservation_call(
            operation.reader_mut(),
            XrefMutationOperation::InsertXrefInstance,
            &host,
        );
    }

    #[test]
    fn insert_accepts_block_owner_locked_destination_and_one_by_one_minsert() {
        let temporary = tempfile::tempdir().unwrap();
        let host = temporary.path().join("host.dwg");
        write_host(&host);
        let mut request = insert_request(&host);
        request.placement = Some(XrefInstancePlacement {
            owner_handle: Some("3f".to_string()),
            owner_type: Some(xrefs::XrefOwnerType::BlockDefinition),
            owner_name: Some("detail".to_string()),
            layer_handle: Some("21".to_string()),
            layer_name: Some("locked".to_string()),
            insertion_point: Some(XrefPoint3 {
                x: 2.0,
                y: 3.0,
                z: 4.0,
            }),
            scale: None,
            rotation_degrees: Some(-90.0),
            normal: None,
            visibility: Some(XrefVisibility::Hidden),
            array: Some(XrefRectangularArray {
                rows: 1,
                columns: 1,
                row_spacing: 0.0,
                column_spacing: 0.0,
            }),
        });
        let mut operation = InsertXrefInstanceOperation::new(
            request,
            reader(Vec::new(), vec![minsert_instance("30", 1, 1)]),
        )
        .unwrap();
        let locked = LockedFixture::new(&host, XrefMutationOperation::InsertXrefInstance);
        operation.validate_locked(&locked.context()).unwrap();
        let validated = operation.validated.as_ref().unwrap();
        assert_eq!(validated.script.owner_handle, "3F");
        assert_eq!(validated.script.layer_name, "LOCKED");
        assert_eq!(validated.script.rotation_degrees, 270.0);
        assert_eq!(validated.script.array.unwrap().rows, 1);
    }

    #[test]
    fn insert_guards_owner_layer_and_recursion_return_exact_codes() {
        let temporary = tempfile::tempdir().unwrap();
        let host = temporary.path().join("host.dwg");
        write_host(&host);
        let locked = LockedFixture::new(&host, XrefMutationOperation::InsertXrefInstance);

        let mut guard = insert_request(&host);
        guard.expected_attachment_handle = Some("B".to_string());
        let mut operation =
            InsertXrefInstanceOperation::new(guard, reader(Vec::new(), Vec::new())).unwrap();
        assert_eq!(
            error_code(operation.validate_locked(&locked.context()).unwrap_err()),
            xrefs::xref_failure_code::EXPECTED_ATTACHMENT_HANDLE_MISMATCH
        );

        let mut dependent_layer = insert_request(&host);
        dependent_layer.placement = Some(XrefInstancePlacement {
            layer_name: Some("SITE|GRID".to_string()),
            ..placement()
        });
        let mut operation =
            InsertXrefInstanceOperation::new(dependent_layer, reader(Vec::new(), Vec::new()))
                .unwrap();
        assert_eq!(
            error_code(operation.validate_locked(&locked.context()).unwrap_err()),
            xrefs::xref_failure_code::LAYER_NOT_HOST_OWNED
        );

        let mut recursive_request = insert_request(&host);
        recursive_request.placement = Some(XrefInstancePlacement {
            owner_handle: Some("3F".to_string()),
            ..placement()
        });
        let mut recursive_reader = reader(Vec::new(), Vec::new());
        recursive_reader
            .before
            .environment
            .block_references
            .insert("A".to_string(), vec!["3F".to_string()]);
        let mut operation =
            InsertXrefInstanceOperation::new(recursive_request, recursive_reader).unwrap();
        assert_eq!(
            error_code(operation.validate_locked(&locked.context()).unwrap_err()),
            xrefs::xref_failure_code::RECURSIVE_BLOCK_REFERENCE
        );
    }

    #[test]
    fn insert_verifier_rejects_identity_replacement_and_extra_entities() {
        let temporary = tempfile::tempdir().unwrap();
        let host = temporary.path().join("host.dwg");
        let staging = temporary.path().join("stage");
        fs::create_dir(&staging).unwrap();
        write_host(&host);
        let fake_reader = reader(Vec::new(), vec![instance("30"), instance("31")]);
        let mut operation =
            InsertXrefInstanceOperation::new(insert_request(&host), fake_reader).unwrap();
        let locked = LockedFixture::new(&host, XrefMutationOperation::InsertXrefInstance);
        operation.validate_locked(&locked.context()).unwrap();
        let sources = Vec::new();
        operation
            .execute(
                &mut FakeEngine::default(),
                &operation_context(&host, &staging, &staging.join("profile.arg"), &sources),
            )
            .unwrap();
        write_sentinel(
            &staging.join(INSERT_SENTINEL_NAME),
            "insert_xref_instance",
            "30",
        );
        operation.reader_mut().use_after();
        let mut file_system = ProductionXrefFileSystem::default();
        let output = file_system.observe_path(&host).unwrap();
        assert_eq!(
            operation
                .verify(&verification_context(&host, &output, &sources))
                .unwrap_err()
                .code,
            XrefTransactionErrorCode::VerificationFailed
        );
    }

    #[test]
    fn update_callback_persists_all_fields_and_allows_locked_destination_layer() {
        let temporary = tempfile::tempdir().unwrap();
        let host = temporary.path().join("host.dwg");
        let staging = temporary.path().join("stage");
        fs::create_dir(&staging).unwrap();
        write_host(&host);
        let properties = BTreeMap::from([
            (
                "insertion_point".to_string(),
                serde_json::json!({"x": 1.0, "y": 2.0, "z": 3.0}),
            ),
            (
                "scale".to_string(),
                serde_json::json!({"x": -2.0, "y": 3.0, "z": 4.0}),
            ),
            ("rotation_degrees".to_string(), serde_json::json!(450.0)),
            (
                "normal".to_string(),
                serde_json::json!({"x": 0.0, "y": 1.0, "z": 0.0}),
            ),
            ("layer_handle".to_string(), serde_json::json!("0x21")),
            ("layer_name".to_string(), serde_json::json!("locked")),
            ("visibility".to_string(), serde_json::json!("hidden")),
        ]);
        let before = instance("10");
        let mut after = before.clone();
        after.insertion_point = XrefPoint3 {
            x: 1.0,
            y: 2.0,
            z: 3.0,
        };
        after.scale = XrefScale3 {
            x: -2.0,
            y: 3.0,
            z: 4.0,
        };
        after.unit_scaling = available_scaling(after.scale);
        after.rotation_degrees = 90.0;
        after.normal = XrefVector3 {
            x: 0.0,
            y: 1.0,
            z: 0.0,
        };
        after.layer_handle = "21".to_string();
        after.layer_name = "LOCKED".to_string();
        after.visibility = XrefVisibility::Hidden;

        let mut operation = UpdateXrefInstanceOperation::new(
            update_request(&host, properties),
            reader(vec![before], vec![after.clone()]),
        )
        .unwrap();
        let locked = LockedFixture::new(&host, XrefMutationOperation::UpdateXrefInstance);
        operation.validate_locked(&locked.context()).unwrap();
        let mut engine = FakeEngine::default();
        let sources = Vec::new();
        operation
            .execute(
                &mut engine,
                &operation_context(&host, &staging, &staging.join("profile.arg"), &sources),
            )
            .unwrap();
        let script = fs::read_to_string(staging.join(UPDATE_SCRIPT_NAME)).unwrap();
        assert!(script.contains("vla-put-Layer object \"LOCKED\""));
        assert!(script.contains("vla-put-XScaleFactor object -2.0"));
        write_sentinel(
            &staging.join(UPDATE_SENTINEL_NAME),
            "update_xref_instance",
            "10",
        );
        operation.reader_mut().use_after();
        let mut file_system = ProductionXrefFileSystem::default();
        let output = file_system.observe_path(&host).unwrap();
        let response = operation
            .verify(&verification_context(&host, &output, &sources))
            .unwrap();
        assert_eq!(response.status, UpdateXrefInstanceStatus::Updated);
        assert_eq!(response.instance, after);
        assert_preservation_call(
            operation.reader_mut(),
            XrefMutationOperation::UpdateXrefInstance,
            &host,
        );
    }

    #[test]
    fn update_context_free_values_precede_source_lock() {
        let temporary = tempfile::tempdir().unwrap();
        let host = temporary.path().join("host.dwg");
        write_host(&host);
        let properties = BTreeMap::from([
            (
                "scale".to_string(),
                serde_json::json!({"x": 0.0, "y": 1.0, "z": 1.0}),
            ),
            ("layer_name".to_string(), serde_json::json!("LOCKED")),
        ]);
        let mut fake_reader = reader(vec![instance("10")], vec![instance("10")]);
        fake_reader.before.environment.layers[0].locked = true;
        assert_eq!(
            error_code(
                UpdateXrefInstanceOperation::new(update_request(&host, properties), fake_reader)
                    .unwrap_err()
            ),
            xrefs::xref_failure_code::INVALID_XREF_SCALE
        );
    }

    #[test]
    fn update_preserves_one_by_one_minsert_class_and_complete_array_when_omitted() {
        let temporary = tempfile::tempdir().unwrap();
        let host = temporary.path().join("host.dwg");
        write_host(&host);
        let before = minsert_instance("10", 1, 1);
        let mut after = before.clone();
        after.visibility = XrefVisibility::Hidden;
        let mut operation = UpdateXrefInstanceOperation::new(
            update_request(
                &host,
                BTreeMap::from([("visibility".to_string(), serde_json::json!("hidden"))]),
            ),
            reader(vec![before.clone()], vec![after]),
        )
        .unwrap();
        let locked = LockedFixture::new(&host, XrefMutationOperation::UpdateXrefInstance);
        operation.validate_locked(&locked.context()).unwrap();
        let expected = &operation.validated.as_ref().unwrap().expected_instance;
        assert_eq!(expected.placement_kind, XrefPlacementKind::RectangularArray);
        assert_eq!(expected.array, before.array);
        assert_eq!(
            operation.validated.as_ref().unwrap().script.placement_kind,
            XrefPlacementKind::RectangularArray
        );
    }

    #[test]
    fn guards_precede_owner_layer_and_clip_checks() {
        let temporary = tempfile::tempdir().unwrap();
        let host = temporary.path().join("host.dwg");
        write_host(&host);
        let mut request = update_request(
            &host,
            BTreeMap::from([("visibility".to_string(), serde_json::json!("hidden"))]),
        );
        request.expected_attachment_handle = Some("B".to_string());
        let mut fake_reader = reader(vec![instance("10")], vec![instance("10")]);
        fake_reader.before.environment.owners[0].write_state = XrefOwnerWriteState::ReadOnly;
        fake_reader.before.environment.layers[0].locked = true;
        fake_reader.before.environment.clips.insert(
            "10".to_string(),
            XrefInstanceClipFacts::Present {
                fingerprint: "clip".to_string(),
            },
        );
        let mut operation = UpdateXrefInstanceOperation::new(request, fake_reader).unwrap();
        let locked = LockedFixture::new(&host, XrefMutationOperation::UpdateXrefInstance);
        assert_eq!(
            error_code(operation.validate_locked(&locked.context()).unwrap_err()),
            xrefs::xref_failure_code::EXPECTED_ATTACHMENT_HANDLE_MISMATCH
        );

        let mut owner_guard = update_request(
            &host,
            BTreeMap::from([("visibility".to_string(), serde_json::json!("hidden"))]),
        );
        owner_guard.expected_owner_handle = Some("2F".to_string());
        let mut operation = UpdateXrefInstanceOperation::new(
            owner_guard,
            reader(vec![instance("10")], vec![instance("10")]),
        )
        .unwrap();
        assert_eq!(
            error_code(operation.validate_locked(&locked.context()).unwrap_err()),
            xrefs::xref_failure_code::EXPECTED_OWNER_HANDLE_MISMATCH
        );
    }

    #[test]
    fn clipped_targets_reject_without_profile_and_pass_only_the_verify_gate() {
        let temporary = tempfile::tempdir().unwrap();
        let host = temporary.path().join("host.dwg");
        write_host(&host);
        let mut fake_reader = reader(vec![instance("10")], vec![instance("10")]);
        fake_reader.before.environment.clips.insert(
            "10".to_string(),
            XrefInstanceClipFacts::Present {
                fingerprint: "clip-v1".to_string(),
            },
        );
        let mut operation = UpdateXrefInstanceOperation::new(
            update_request(
                &host,
                BTreeMap::from([("visibility".to_string(), serde_json::json!("hidden"))]),
            ),
            fake_reader,
        )
        .unwrap();
        let locked = LockedFixture::new(&host, XrefMutationOperation::UpdateXrefInstance);
        assert_eq!(
            error_code(operation.validate_locked(&locked.context()).unwrap_err()),
            xrefs::xref_failure_code::UNSUPPORTED_XREF_CLIP_DATA
        );

        let row = XrefMutationCapabilityRow {
            row_id: "test-verify".to_string(),
            host_format: XrefHostFormat::Dwg,
            drawing_version: "AC1032".to_string(),
            dxf_form: XrefDxfForm::NotApplicable,
            code_page: None,
            operations: vec![XrefMutationOperation::UpdateXrefInstance],
            preservation_verifier_profile_id: "preservation".to_string(),
            bind_verifier_profile_id: None,
            clip_policy: XrefClipPolicy::Verify,
            clip_verifier_profile_id: Some("clip".to_string()),
        };
        let preservation = XrefPreservationVerifierProfile {
            profile_id: "preservation".to_string(),
            absolute_tolerance: 0.0,
            relative_tolerance: 0.0,
            object_classes: Vec::new(),
            symbol_types: Vec::new(),
            mapped_identity_fields: Vec::new(),
            authorized_differences: Vec::new(),
            profile_default_unit_states: Vec::new(),
        };
        let clip = XrefClipVerifierProfile {
            profile_id: "clip".to_string(),
            absolute_tolerance: 0.0,
            relative_tolerance: 0.0,
            mapped_identity_fields: Vec::new(),
            profile_default_unit_states: Vec::new(),
            clip_fields: Vec::new(),
        };
        let admission = XrefMutationAdmission {
            capability: &row,
            preservation_profile: &preservation,
            bind_profile: None,
            clip_profile: Some(&clip),
        };
        let context = XrefLockedMutationContext {
            host_path: &locked.path,
            host: &locked.observation,
            format: &locked.format,
            admission: &admission,
        };
        assert_eq!(
            validate_clip_policy(
                &context,
                &XrefInstanceClipFacts::Present {
                    fingerprint: "clip-v1".to_string(),
                },
                "10"
            )
            .unwrap(),
            Some("clip-v1".to_string())
        );
        assert_eq!(
            error_code(
                validate_clip_policy(&context, &XrefInstanceClipFacts::Unobservable, "10")
                    .unwrap_err()
            ),
            xrefs::xref_failure_code::UNSUPPORTED_XREF_CLIP_DATA
        );
    }

    #[test]
    fn delete_callback_returns_predelete_record_and_leaves_final_attachment_at_zero() {
        let temporary = tempfile::tempdir().unwrap();
        let host = temporary.path().join("host.dwg");
        let staging = temporary.path().join("stage");
        fs::create_dir(&staging).unwrap();
        write_host(&host);
        let deleted = instance("10");
        let mut operation = DeleteXrefInstanceOperation::new(
            delete_request(&host),
            reader(vec![deleted.clone()], Vec::new()),
        )
        .unwrap();
        let locked = LockedFixture::new(&host, XrefMutationOperation::DeleteXrefInstance);
        operation.validate_locked(&locked.context()).unwrap();
        let sources = Vec::new();
        let mut engine = FakeEngine::default();
        operation
            .execute(
                &mut engine,
                &operation_context(&host, &staging, &staging.join("profile.arg"), &sources),
            )
            .unwrap();
        assert!(fs::read_to_string(staging.join(DELETE_SCRIPT_NAME))
            .unwrap()
            .contains("vla-Delete object"));
        write_sentinel(
            &staging.join(DELETE_SENTINEL_NAME),
            "delete_xref_instance",
            "10",
        );
        operation.reader_mut().use_after();
        let mut file_system = ProductionXrefFileSystem::default();
        let output = file_system.observe_path(&host).unwrap();
        let response = operation
            .verify(&verification_context(&host, &output, &sources))
            .unwrap();
        assert_eq!(response.status, DeleteXrefInstanceStatus::Deleted);
        assert_eq!(response.instance, deleted);
        assert_preservation_call(
            operation.reader(),
            XrefMutationOperation::DeleteXrefInstance,
            &host,
        );
        assert_eq!(
            operation.reader().snapshot().attachments[0].instance_count,
            0
        );
        assert!(operation.reader().snapshot().instances.is_empty());
    }

    #[test]
    fn delete_rejects_locked_source_and_unverifiable_clip() {
        let temporary = tempfile::tempdir().unwrap();
        let host = temporary.path().join("host.dwg");
        write_host(&host);
        let locked = LockedFixture::new(&host, XrefMutationOperation::DeleteXrefInstance);

        let mut locked_reader = reader(vec![instance("10")], Vec::new());
        locked_reader.before.environment.layers[0].locked = true;
        let mut operation =
            DeleteXrefInstanceOperation::new(delete_request(&host), locked_reader).unwrap();
        assert_eq!(
            error_code(operation.validate_locked(&locked.context()).unwrap_err()),
            xrefs::xref_failure_code::XREF_INSTANCE_LOCKED
        );

        let mut clipped_reader = reader(vec![instance("10")], Vec::new());
        clipped_reader.before.environment.clips.insert(
            "10".to_string(),
            XrefInstanceClipFacts::Present {
                fingerprint: "clip".to_string(),
            },
        );
        let mut operation =
            DeleteXrefInstanceOperation::new(delete_request(&host), clipped_reader).unwrap();
        assert_eq!(
            error_code(operation.validate_locked(&locked.context()).unwrap_err()),
            xrefs::xref_failure_code::UNSUPPORTED_XREF_CLIP_DATA
        );
    }

    #[test]
    fn delete_verifier_rejects_a_target_that_survives_or_a_missing_parent_attachment() {
        let temporary = tempfile::tempdir().unwrap();
        let host = temporary.path().join("host.dwg");
        let staging = temporary.path().join("stage");
        fs::create_dir(&staging).unwrap();
        write_host(&host);
        let mut operation = DeleteXrefInstanceOperation::new(
            delete_request(&host),
            reader(vec![instance("10")], vec![instance("10")]),
        )
        .unwrap();
        let locked = LockedFixture::new(&host, XrefMutationOperation::DeleteXrefInstance);
        operation.validate_locked(&locked.context()).unwrap();
        let sources = Vec::new();
        operation
            .execute(
                &mut FakeEngine::default(),
                &operation_context(&host, &staging, &staging.join("profile.arg"), &sources),
            )
            .unwrap();
        write_sentinel(
            &staging.join(DELETE_SENTINEL_NAME),
            "delete_xref_instance",
            "10",
        );
        operation.reader_mut().use_after();
        let mut file_system = ProductionXrefFileSystem::default();
        let output = file_system.observe_path(&host).unwrap();
        assert_eq!(
            operation
                .verify(&verification_context(&host, &output, &sources))
                .unwrap_err()
                .code,
            XrefTransactionErrorCode::VerificationFailed
        );
    }

    #[derive(Debug, Clone)]
    struct StaticFactSource(XrefInstanceMutationEnvironment);

    impl XrefInstanceMutationFactSource for StaticFactSource {
        fn read_environment(
            &mut self,
            _host: &xref_io::LoadedXrefHost,
        ) -> Result<XrefInstanceMutationEnvironment, XrefTransactionError> {
            Ok(self.0.clone())
        }

        fn read_preservation_snapshot(
            &mut self,
            _host: &xref_io::LoadedXrefHost,
        ) -> Result<XrefAttachmentMutationSnapshot, XrefTransactionError> {
            Err(domain_error(
                xrefs::xref_failure_code::UNSUPPORTED_XREF_DATA,
                "static fact source has no whole-drawing preservation projection",
            ))
        }

        fn verify_preservation(
            &mut self,
            _verification: &XrefPreservationVerification<'_>,
        ) -> Result<(), XrefTransactionError> {
            Err(domain_error(
                xrefs::xref_failure_code::UNSUPPORTED_XREF_DATA,
                "static fact source has no whole-drawing preservation verifier",
            ))
        }
    }

    #[test]
    fn portable_reader_adapter_reuses_one_reader_snapshot_for_locked_mutation_facts() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .unwrap()
            .join("tests/fixtures/xrefs/portable-evidence-ascii.dxf");
        let facts = StaticFactSource(environment());
        let mut reader = PortableXrefInstanceMutationReader::new(facts);
        let attachments = reader.list_attachments(&fixture).unwrap();
        assert_eq!(attachments.len(), 3);
        let instances = reader.list_attachment_instances(&fixture, "F").unwrap();
        assert_eq!(instances.len(), 2);
        assert_eq!(
            reader.get_instance(&fixture, "20").unwrap().unwrap().handle,
            "20"
        );
        assert_eq!(reader.read_environment(&fixture).unwrap().owners.len(), 3);
        assert_eq!(reader.hosts.len(), 1);
        let facts = reader.into_fact_source();
        assert_eq!(facts.0.layers.len(), 3);
    }
}
