use std::collections::BTreeSet;

use autocad_reader::contract::xrefs::{
    xref_name_eq, XrefAttachmentRecord, XrefInstanceListOptions, XrefInstanceRecord, XrefSelector,
};
use autocad_reader::{DrawingReadSession, XrefReadSession};

use super::xrefs::XrefPostcondition;
use super::WriteError;

#[derive(Debug)]
pub(super) enum ReaderVerification {
    Verified,
    Unavailable { reason_code: String },
}

fn projection_failure(
    code: &'static str,
    message: &'static str,
    error: impl std::fmt::Display,
) -> WriteError {
    WriteError::verification(code, message).with_internal_detail(error.to_string())
}

fn xref_session(reader: &DrawingReadSession) -> Result<XrefReadSession, WriteError> {
    reader.xref_session().map_err(|error| {
        projection_failure(
            "candidate_xref_projection_failed",
            "independent XREF projection rejected the encoded candidate",
            error,
        )
    })
}

fn attachment(session: &XrefReadSession, handle: &str) -> Result<XrefAttachmentRecord, WriteError> {
    session
        .get_attachment(&XrefSelector {
            handle: Some(handle.to_string()),
            name: None,
        })
        .map_err(|error| {
            if error.code() == "xref_not_found" {
                WriteError::verification(
                    "xref_attachment_postcondition_failed",
                    "independent reader projection is missing the expected XREF attachment",
                )
            } else {
                projection_failure(
                    "candidate_xref_attachment_projection_failed",
                    "independent reader could not project the expected XREF attachment",
                    error,
                )
            }
        })
}

fn instances(
    session: &XrefReadSession,
    attachment_handle: &str,
) -> Result<Vec<XrefInstanceRecord>, WriteError> {
    session
        .list_instances(&XrefInstanceListOptions {
            attachment_handle: Some(attachment_handle.to_string()),
            ..Default::default()
        })
        .map_err(|error| {
            projection_failure(
                "candidate_xref_instance_projection_failed",
                "independent reader could not project the XREF attachment instances",
                error,
            )
        })
}

fn same_float(left: f64, right: f64) -> bool {
    (left - right).abs() <= 1e-8
}

fn same_instance(left: &XrefInstanceRecord, right: &XrefInstanceRecord) -> bool {
    left.handle == right.handle
        && left.attachment_handle == right.attachment_handle
        && xref_name_eq(&left.attachment_name, &right.attachment_name)
        && left.owner_handle == right.owner_handle
        && left.owner_type == right.owner_type
        && xref_name_eq(&left.owner_name, &right.owner_name)
        && left.layer_handle == right.layer_handle
        && xref_name_eq(&left.layer_name, &right.layer_name)
        && same_float(left.insertion_point.x, right.insertion_point.x)
        && same_float(left.insertion_point.y, right.insertion_point.y)
        && same_float(left.insertion_point.z, right.insertion_point.z)
        && same_float(left.scale.x, right.scale.x)
        && same_float(left.scale.y, right.scale.y)
        && same_float(left.scale.z, right.scale.z)
        && same_float(left.rotation_degrees, right.rotation_degrees)
        && same_float(left.normal.x, right.normal.x)
        && same_float(left.normal.y, right.normal.y)
        && same_float(left.normal.z, right.normal.z)
        && left.visibility == right.visibility
        && left.placement_kind == right.placement_kind
        && left.array == right.array
}

pub(super) fn verify(
    reader: &DrawingReadSession,
    expected: &XrefPostcondition,
) -> Result<ReaderVerification, WriteError> {
    let session = xref_session(reader)?;
    match expected {
        XrefPostcondition::AttachmentPresent {
            handle,
            name,
            saved_path,
            reference_type,
            instance_handles,
        } => {
            let actual = attachment(&session, handle)?;
            let actual_instances = instances(&session, handle)?;
            let actual_handles = actual_instances
                .iter()
                .map(|instance| instance.handle.clone())
                .collect::<BTreeSet<_>>();
            let expected_handles = instance_handles.iter().cloned().collect::<BTreeSet<_>>();
            if actual.handle != *handle
                || !xref_name_eq(&actual.name, name)
                || actual.saved_path != *saved_path
                || actual.reference_type != *reference_type
                || actual.instance_count != instance_handles.len() as u64
                || actual_handles.len() != actual_instances.len()
                || expected_handles.len() != instance_handles.len()
                || actual_handles != expected_handles
            {
                return Err(WriteError::verification(
                    "xref_attachment_postcondition_failed",
                    "independent reader projection differs from the planned XREF attachment",
                ));
            }
            Ok(ReaderVerification::Verified)
        }
        XrefPostcondition::AttachmentAbsent { handle, name } => {
            let attachments = session.list_attachments().map_err(|error| {
                projection_failure(
                    "candidate_xref_attachment_projection_failed",
                    "independent reader could not enumerate XREF attachments",
                    error,
                )
            })?;
            if attachments.iter().any(|attachment| {
                attachment.handle.eq_ignore_ascii_case(handle)
                    || xref_name_eq(&attachment.name, name)
            }) {
                return Err(WriteError::verification(
                    "xref_attachment_still_present",
                    "independent reader projection still contains the detached XREF",
                ));
            }
            Ok(ReaderVerification::Verified)
        }
        XrefPostcondition::InstancePresent { expected } => {
            let actual = session.get_instance(&expected.handle).map_err(|error| {
                if error.code() == "xref_instance_not_found" {
                    WriteError::verification(
                        "xref_instance_postcondition_failed",
                        "independent reader projection is missing the expected XREF instance",
                    )
                } else {
                    projection_failure(
                        "candidate_xref_instance_projection_failed",
                        "independent reader could not project the expected XREF instance",
                        error,
                    )
                }
            })?;
            if !same_instance(&actual, expected) {
                return Err(WriteError::verification(
                    "xref_instance_postcondition_failed",
                    "independent reader projection differs from the planned XREF instance",
                ));
            }
            Ok(ReaderVerification::Verified)
        }
        XrefPostcondition::InstanceAbsent {
            handle,
            attachment_handle,
            attachment_name,
        } => {
            let actual_attachment = attachment(&session, attachment_handle)?;
            if !xref_name_eq(&actual_attachment.name, attachment_name) {
                return Err(WriteError::verification(
                    "xref_attachment_postcondition_failed",
                    "independent reader projection changed the retained XREF attachment",
                ));
            }
            if instances(&session, attachment_handle)?
                .iter()
                .any(|instance| instance.handle.eq_ignore_ascii_case(handle))
            {
                return Err(WriteError::verification(
                    "xref_instance_still_present",
                    "independent reader projection still contains the deleted XREF instance",
                ));
            }
            Ok(ReaderVerification::Verified)
        }
        XrefPostcondition::LoadState { .. } => Ok(ReaderVerification::Unavailable {
            reason_code: "xref_load_state_unobservable_by_independent_reader".to_string(),
        }),
        XrefPostcondition::Unmaterialized { reason_code } => Ok(ReaderVerification::Unavailable {
            reason_code: reason_code.clone(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use acadrust::{CadDocument, DwgWriter};
    use autocad_reader::{
        DrawingFormat as ReaderFormat, DrawingSnapshot as ReaderSnapshot, Reader,
    };

    use super::*;
    use crate::contract::{AttachXref, ReferenceType};
    use crate::DrawingFormat;

    fn attached_candidate() -> (DrawingReadSession, XrefAttachmentRecord, XrefInstanceRecord) {
        let mut document = CadDocument::new();
        let bridge = crate::xref_handle_bridge::XrefHandleBridge::identity(&document);
        let mutation = crate::xrefs::attach(
            &mut document,
            DrawingFormat::Dwg,
            &mut BTreeMap::new(),
            &bridge,
            &AttachXref {
                xref_path: "site.dwg".to_string(),
                name: Some("SITE".to_string()),
                reference_type: ReferenceType::Attachment,
                search_paths: None,
                placement: None,
                unit_assumptions: None,
            },
        )
        .unwrap();
        let reader = Reader::open_snapshot(ReaderSnapshot::new(
            ReaderFormat::Dwg,
            DwgWriter::write_to_vec(&document).unwrap(),
        ))
        .unwrap();
        (reader, mutation.result.attachment, mutation.result.instance)
    }

    #[test]
    fn reader_contradictions_keep_attachment_and_instance_reason_codes_distinct() {
        let (reader, attachment, instance) = attached_candidate();

        let error = verify(
            &reader,
            &XrefPostcondition::AttachmentPresent {
                handle: attachment.handle.clone(),
                name: attachment.name.clone(),
                saved_path: "different.dwg".to_string(),
                reference_type: attachment.reference_type,
                instance_handles: vec![instance.handle.clone()],
            },
        )
        .unwrap_err();
        assert_eq!(error.code(), "xref_attachment_postcondition_failed");

        let error = verify(
            &reader,
            &XrefPostcondition::AttachmentAbsent {
                handle: attachment.handle.clone(),
                name: attachment.name.clone(),
            },
        )
        .unwrap_err();
        assert_eq!(error.code(), "xref_attachment_still_present");

        let mut missing = instance.clone();
        missing.handle = "DEAD".to_string();
        let error = verify(
            &reader,
            &XrefPostcondition::InstancePresent {
                expected: Box::new(missing),
            },
        )
        .unwrap_err();
        assert_eq!(error.code(), "xref_instance_postcondition_failed");

        let error = verify(
            &reader,
            &XrefPostcondition::InstanceAbsent {
                handle: instance.handle,
                attachment_handle: attachment.handle,
                attachment_name: attachment.name,
            },
        )
        .unwrap_err();
        assert_eq!(error.code(), "xref_instance_still_present");
    }
}
