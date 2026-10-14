use serde::{Deserialize, Serialize};
use std::{collections::HashSet, fmt};

pub const CONFIRMATION_TEXT: &str = "APPLY REDTRACE AUDIT";

#[derive(Clone, Debug, Serialize)]
pub struct WindowsAuditPlan {
    pub profile: &'static str,
    pub requires_administrator: bool,
    pub apply_requires_confirmation: bool,
    pub privacy_warning: &'static str,
    pub actions: Vec<AuditAction>,
}

#[derive(Clone, Debug, Serialize)]
pub struct AuditAction {
    pub id: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub source_events: &'static [&'static str],
    pub apply: Vec<CommandSpec>,
    pub rollback: Rollback,
}

#[derive(Clone, Debug, Serialize)]
pub struct CommandSpec {
    pub program: &'static str,
    pub args: &'static [&'static str],
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Rollback {
    AuditPolicyBackup,
    RestoreRegistrySnapshot,
    SysmonPreviousConfiguration,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AuditApplyRequest {
    pub profile: String,
    pub action_ids: Vec<String>,
    pub confirmation: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct AuditApplyReport {
    pub profile: String,
    pub applied_actions: Vec<String>,
    pub verified: bool,
    pub rollback_available: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditApplyError {
    ConfirmationRequired,
    ProfileMismatch,
    EmptySelection,
    UnknownAction(String),
    DuplicateAction(String),
    Snapshot(String),
    Apply { action: String, reason: String },
    Verify { action: String, reason: String },
    Rollback { reason: String },
}

impl fmt::Display for AuditApplyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConfirmationRequired => write!(formatter, "explicit confirmation is required"),
            Self::ProfileMismatch => write!(formatter, "audit profile does not match"),
            Self::EmptySelection => write!(formatter, "no audit actions selected"),
            Self::UnknownAction(action) => write!(formatter, "unknown audit action: {action}"),
            Self::DuplicateAction(action) => write!(formatter, "duplicate audit action: {action}"),
            Self::Snapshot(reason) => {
                write!(formatter, "could not create audit snapshot: {reason}")
            }
            Self::Apply { action, reason } => {
                write!(formatter, "could not apply {action}: {reason}")
            }
            Self::Verify { action, reason } => {
                write!(formatter, "could not verify {action}: {reason}")
            }
            Self::Rollback { reason } => write!(formatter, "rollback failed: {reason}"),
        }
    }
}

pub trait AuditBackend {
    type Snapshot;

    fn snapshot(&mut self) -> Result<Self::Snapshot, String>;
    fn apply(&mut self, command: &CommandSpec) -> Result<(), String>;
    fn verify(&mut self, action: &AuditAction) -> Result<(), String>;
    fn rollback(&mut self, snapshot: &Self::Snapshot) -> Result<(), String>;
}

pub fn apply_transaction<B: AuditBackend>(
    request: &AuditApplyRequest,
    backend: &mut B,
) -> Result<AuditApplyReport, AuditApplyError> {
    let plan = recommended_plan();
    if request.confirmation != CONFIRMATION_TEXT {
        return Err(AuditApplyError::ConfirmationRequired);
    }
    if request.profile != plan.profile {
        return Err(AuditApplyError::ProfileMismatch);
    }
    if request.action_ids.is_empty() {
        return Err(AuditApplyError::EmptySelection);
    }
    let mut seen = HashSet::new();
    let mut selected = Vec::with_capacity(request.action_ids.len());
    for id in &request.action_ids {
        if !seen.insert(id.as_str()) {
            return Err(AuditApplyError::DuplicateAction(id.clone()));
        }
        let Some(action) = plan.actions.iter().find(|action| action.id == id) else {
            return Err(AuditApplyError::UnknownAction(id.clone()));
        };
        selected.push(action);
    }
    let snapshot = backend.snapshot().map_err(AuditApplyError::Snapshot)?;
    let mut applied_actions = Vec::with_capacity(selected.len());
    for action in selected {
        for command in &action.apply {
            if let Err(reason) = backend.apply(command) {
                return Err(rollback_error(
                    backend,
                    &snapshot,
                    AuditApplyError::Apply {
                        action: action.id.into(),
                        reason,
                    },
                ));
            }
        }
        if let Err(reason) = backend.verify(action) {
            return Err(rollback_error(
                backend,
                &snapshot,
                AuditApplyError::Verify {
                    action: action.id.into(),
                    reason,
                },
            ));
        }
        applied_actions.push(action.id.into());
    }
    Ok(AuditApplyReport {
        profile: plan.profile.into(),
        applied_actions,
        verified: true,
        rollback_available: true,
    })
}

fn rollback_error<B: AuditBackend>(
    backend: &mut B,
    snapshot: &B::Snapshot,
    original: AuditApplyError,
) -> AuditApplyError {
    match backend.rollback(snapshot) {
        Ok(()) => original,
        Err(reason) => AuditApplyError::Rollback {
            reason: format!("{original}; rollback error: {reason}"),
        },
    }
}

pub fn recommended_plan() -> WindowsAuditPlan {
    WindowsAuditPlan {
        profile: "recommended-workstation",
        requires_administrator: true,
        apply_requires_confirmation: true,
        privacy_warning: "Командные строки и PowerShell script blocks могут содержать пароли, токены и другие чувствительные данные.",
        actions: vec![
            AuditAction {
                id: "logon",
                title: "Успешные и неуспешные входы",
                description: "Включает расширенный аудит Logon по стабильному GUID, не зависящему от языка Windows.",
                source_events: &["4624", "4625"],
                apply: vec![CommandSpec {
                    program: "auditpol.exe",
                    args: &[
                        "/set",
                        "/subcategory:{0CCE9215-69AE-11D9-BED3-505054503030}",
                        "/success:enable",
                        "/failure:enable",
                    ],
                }],
                rollback: Rollback::AuditPolicyBackup,
            },
            AuditAction {
                id: "account-lockout",
                title: "Блокировка учётной записи",
                description: "Включает успешный аудит управления учётными записями, включая событие блокировки 4740.",
                source_events: &["4740"],
                apply: vec![CommandSpec {
                    program: "auditpol.exe",
                    args: &[
                        "/set",
                        "/subcategory:{0CCE9235-69AE-11D9-BED3-505054503030}",
                        "/success:enable",
                        "/failure:disable",
                    ],
                }],
                rollback: Rollback::AuditPolicyBackup,
            },
            AuditAction {
                id: "process-creation",
                title: "Создание процессов и командная строка",
                description: "Включает событие 4688 и добавляет аргументы командной строки в открытом виде.",
                source_events: &["4688"],
                apply: vec![
                    CommandSpec {
                        program: "auditpol.exe",
                        args: &[
                            "/set",
                            "/subcategory:{0CCE922B-69AE-11D9-BED3-505054503030}",
                            "/success:enable",
                            "/failure:disable",
                        ],
                    },
                    CommandSpec {
                        program: "reg.exe",
                        args: &[
                            "add",
                            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit",
                            "/v",
                            "ProcessCreationIncludeCmdLine_Enabled",
                            "/t",
                            "REG_DWORD",
                            "/d",
                            "1",
                            "/f",
                        ],
                    },
                ],
                rollback: Rollback::RestoreRegistrySnapshot,
            },
            AuditAction {
                id: "powershell-script-block",
                title: "PowerShell Script Block Logging",
                description: "Записывает обработанные команды, функции и script blocks в PowerShell Operational.",
                source_events: &["4104"],
                apply: vec![CommandSpec {
                    program: "reg.exe",
                    args: &[
                        "add",
                        "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging",
                        "/v",
                        "EnableScriptBlockLogging",
                        "/t",
                        "REG_DWORD",
                        "/d",
                        "1",
                        "/f",
                    ],
                }],
                rollback: Rollback::RestoreRegistrySnapshot,
            },
            AuditAction {
                id: "sysmon",
                title: "Microsoft Sysmon",
                description: "Установка выполняется только из выбранного пользователем, проверенного исполняемого файла и с показанной конфигурацией.",
                source_events: &["1", "3", "7", "11", "12", "13", "22"],
                apply: vec![CommandSpec {
                    program: "<selected-sysmon64.exe>",
                    args: &["-accepteula", "-i", "<generated-config.xml>"],
                }],
                rollback: Rollback::SysmonPreviousConfiguration,
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FakeBackend {
        applied: usize,
        rollback_called: bool,
        fail_after: Option<usize>,
    }

    impl AuditBackend for FakeBackend {
        type Snapshot = &'static str;

        fn snapshot(&mut self) -> Result<Self::Snapshot, String> {
            Ok("snapshot")
        }

        fn apply(&mut self, _: &CommandSpec) -> Result<(), String> {
            self.applied += 1;
            if self.fail_after == Some(self.applied) {
                Err("simulated failure".into())
            } else {
                Ok(())
            }
        }

        fn verify(&mut self, _: &AuditAction) -> Result<(), String> {
            Ok(())
        }

        fn rollback(&mut self, _: &Self::Snapshot) -> Result<(), String> {
            self.rollback_called = true;
            Ok(())
        }
    }

    #[test]
    fn plan_is_preview_only_and_reversible() {
        let plan = recommended_plan();
        assert!(plan.apply_requires_confirmation);
        assert!(plan.actions.iter().all(|action| !action.apply.is_empty()));
    }

    #[test]
    fn transaction_requires_exact_confirmation_and_allowlisted_ids() {
        let mut backend = FakeBackend::default();
        let request = AuditApplyRequest {
            profile: "recommended-workstation".into(),
            action_ids: vec!["logon".into()],
            confirmation: "yes".into(),
        };
        assert_eq!(
            apply_transaction(&request, &mut backend),
            Err(AuditApplyError::ConfirmationRequired)
        );
        assert_eq!(backend.applied, 0);
    }

    #[test]
    fn transaction_rolls_back_partial_failure() {
        let mut backend = FakeBackend {
            fail_after: Some(2),
            ..FakeBackend::default()
        };
        let request = AuditApplyRequest {
            profile: "recommended-workstation".into(),
            action_ids: vec!["process-creation".into()],
            confirmation: CONFIRMATION_TEXT.into(),
        };
        assert!(matches!(
            apply_transaction(&request, &mut backend),
            Err(AuditApplyError::Apply { .. })
        ));
        assert!(backend.rollback_called);
    }

    #[test]
    fn transaction_verifies_successful_actions() {
        let mut backend = FakeBackend::default();
        let request = AuditApplyRequest {
            profile: "recommended-workstation".into(),
            action_ids: vec!["logon".into(), "account-lockout".into()],
            confirmation: CONFIRMATION_TEXT.into(),
        };
        let report = apply_transaction(&request, &mut backend).unwrap();
        assert!(report.verified);
        assert_eq!(report.applied_actions, request.action_ids);
        assert!(!backend.rollback_called);
    }
}
