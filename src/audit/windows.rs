use serde::Serialize;

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
                description: "Записывает отказы, связанные с блокировкой локальной или доменной учётной записи.",
                source_events: &["4740"],
                apply: vec![CommandSpec {
                    program: "auditpol.exe",
                    args: &[
                        "/set",
                        "/subcategory:{0CCE9217-69AE-11D9-BED3-505054503030}",
                        "/success:disable",
                        "/failure:enable",
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

    #[test]
    fn plan_is_preview_only_and_reversible() {
        let plan = recommended_plan();
        assert!(plan.apply_requires_confirmation);
        assert!(plan.actions.iter().all(|action| !action.apply.is_empty()));
    }
}
