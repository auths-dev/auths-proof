//! Trusted parameterized SQL compiler for the closed update language.

use serde::{Deserialize, Serialize};

use crate::{
    action::PostgresBoundedUpdateIntentV1,
    canonical::sha256,
    schema::{
        DigestHex, IsolationLevelV1, PgIdentifier, PostgresVerifierConfigurationV1,
        ValidationError, ValueKindV1,
    },
    value::TypedValueV1,
};

const TEMPLATE_VERSION: &str = "auths-postgresql-bounded-update-sql/1";

/// A protocol parameter and its semantic role.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParameterBindingV1 {
    pub position: u32,
    pub role: String,
    pub column: PgIdentifier,
    pub value: TypedValueV1,
}

/// SQL known to originate only from validated identifiers and a fixed grammar.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CompiledBoundedUpdate {
    pub isolation: IsolationLevelV1,
    pub statement_timeout_ms: u32,
    pub lock_timeout_ms: u32,
    pub lock_sql: String,
    pub update_sql: String,
    pub parameters: Vec<ParameterBindingV1>,
    pub returning_columns: Vec<PgIdentifier>,
    pub template_digest: DigestHex,
}

fn cast_expression(
    position: u32,
    kind: &ValueKindV1,
    enum_name: Option<&PgIdentifier>,
    enum_schema: &PgIdentifier,
) -> String {
    match kind {
        ValueKindV1::Boolean => format!("CAST(${position}::text AS boolean)"),
        ValueKindV1::Int64 => format!("CAST(${position}::text AS bigint)"),
        ValueKindV1::Text => format!("${position}::text"),
        ValueKindV1::Uuid => format!("CAST(${position}::text AS uuid)"),
        ValueKindV1::Decimal => format!("CAST(${position}::text AS numeric)"),
        ValueKindV1::TimestampUtc => {
            format!("to_timestamp(CAST(${position}::text AS double precision) / 1000000.0)")
        }
        ValueKindV1::EnumText => format!(
            "CAST(${position}::text AS {}.{})",
            enum_schema.quoted(),
            enum_name.expect("validated enum constraint").quoted()
        ),
    }
}

fn select_expression(column: &PgIdentifier) -> String {
    format!("{}::text AS {}", column.quoted(), column.quoted())
}

/// Compiles exact tenant, primary-key, version, and assignment parameters.
pub fn compile_statement(
    intent: &PostgresBoundedUpdateIntentV1,
    configuration: &PostgresVerifierConfigurationV1,
) -> Result<CompiledBoundedUpdate, ValidationError> {
    intent.validate()?;
    let relation = configuration
        .relation(
            &intent.database_name,
            &intent.schema_name,
            &intent.table_name,
        )
        .ok_or(ValidationError::InvalidConfiguration)?;
    let qualified = format!(
        "{}.{}",
        intent.schema_name.quoted(),
        intent.table_name.quoted()
    );
    let mut parameters = Vec::new();
    let tenant_position = 1_u32;
    parameters.push(ParameterBindingV1 {
        position: tenant_position,
        role: "tenant".into(),
        column: intent.tenant_column.clone(),
        value: intent.tenant_value.clone(),
    });
    let tenant_predicate = format!(
        "{}::text = ${tenant_position}::text",
        intent.tenant_column.quoted()
    );

    let mut row_predicates = Vec::with_capacity(intent.rows.len());
    for (row_index, row) in intent.rows.iter().enumerate() {
        let mut terms = Vec::with_capacity(row.primary_key.len() + 1);
        for named in &row.primary_key {
            let position =
                u32::try_from(parameters.len() + 1).map_err(|_| ValidationError::LimitExceeded)?;
            parameters.push(ParameterBindingV1 {
                position,
                role: format!("row-{row_index}-primary-key"),
                column: named.column.clone(),
                value: named.value.clone(),
            });
            terms.push(format!(
                "{}::text = ${position}::text",
                named.column.quoted()
            ));
        }
        let position =
            u32::try_from(parameters.len() + 1).map_err(|_| ValidationError::LimitExceeded)?;
        parameters.push(ParameterBindingV1 {
            position,
            role: format!("row-{row_index}-version"),
            column: relation.row_version_column.clone(),
            value: TypedValueV1::Int64(row.row_version),
        });
        terms.push(format!(
            "{} = CAST(${position}::text AS bigint)",
            relation.row_version_column.quoted()
        ));
        row_predicates.push(format!("({})", terms.join(" AND ")));
    }
    let exact_predicate = format!("{tenant_predicate} AND ({})", row_predicates.join(" OR "));

    let mut assignments = Vec::with_capacity(intent.assignments.len());
    for assignment in &intent.assignments {
        let constraint = relation
            .assignment_constraints
            .iter()
            .find(|(column, _)| column == &assignment.column)
            .map(|(_, constraint)| constraint)
            .ok_or(ValidationError::InvalidConfiguration)?;
        let position =
            u32::try_from(parameters.len() + 1).map_err(|_| ValidationError::LimitExceeded)?;
        parameters.push(ParameterBindingV1 {
            position,
            role: "assignment".into(),
            column: assignment.column.clone(),
            value: assignment.value.clone(),
        });
        let expression = if matches!(assignment.value, TypedValueV1::Null(_)) {
            format!(
                "CAST(NULL AS {})",
                match constraint.kind {
                    ValueKindV1::Boolean => "boolean".into(),
                    ValueKindV1::Int64 => "bigint".into(),
                    ValueKindV1::Text => "text".into(),
                    ValueKindV1::Uuid => "uuid".into(),
                    ValueKindV1::Decimal => "numeric".into(),
                    ValueKindV1::TimestampUtc => "timestamptz".into(),
                    ValueKindV1::EnumText => format!(
                        "{}.{}",
                        intent.schema_name.quoted(),
                        constraint
                            .enum_name
                            .as_ref()
                            .expect("validated enum constraint")
                            .quoted()
                    ),
                }
            )
        } else {
            cast_expression(
                position,
                &constraint.kind,
                constraint.enum_name.as_ref(),
                &intent.schema_name,
            )
        };
        assignments.push(format!("{} = {expression}", assignment.column.quoted()));
    }
    assignments.push(format!(
        "{} = {} + 1",
        relation.row_version_column.quoted(),
        relation.row_version_column.quoted()
    ));

    let mut returning = intent.primary_key_columns.clone();
    for row in &intent.rows {
        for before in &row.before_value_commitments {
            if !returning.contains(&before.column) {
                returning.push(before.column.clone());
            }
        }
    }
    for assignment in &intent.assignments {
        if !returning.contains(&assignment.column) {
            returning.push(assignment.column.clone());
        }
    }
    if !returning.contains(&relation.row_version_column) {
        returning.push(relation.row_version_column.clone());
    }
    returning.sort();
    let returning_sql = returning
        .iter()
        .map(select_expression)
        .collect::<Vec<_>>()
        .join(", ");
    let lock_sql =
        format!("SELECT {returning_sql} FROM {qualified} WHERE {exact_predicate} FOR UPDATE");
    let update_sql = format!(
        "UPDATE {qualified} SET {} WHERE {exact_predicate} RETURNING {returning_sql}",
        assignments.join(", ")
    );
    let template_material = format!(
        "{TEMPLATE_VERSION}\nSERIALIZABLE\n{lock_sql}\n{update_sql}\nstatement_timeout={}\nlock_timeout={}",
        configuration.statement_timeout_ms(),
        configuration.lock_timeout_ms()
    );
    Ok(CompiledBoundedUpdate {
        isolation: IsolationLevelV1::Serializable,
        statement_timeout_ms: configuration.statement_timeout_ms(),
        lock_timeout_ms: configuration.lock_timeout_ms(),
        lock_sql,
        update_sql,
        parameters,
        returning_columns: returning,
        template_digest: sha256(template_material.as_bytes()),
    })
}

#[cfg(test)]
mod tests {
    use crate::test_support::fixture;

    use super::*;

    #[test]
    fn compiler_never_interpolates_values() {
        let mut fixture = fixture();
        fixture.intent.tenant_value =
            TypedValueV1::text("tenant' OR true; DROP TABLE demo_accounts;--").unwrap();
        let compiled = compile_statement(&fixture.intent, &fixture.configuration).unwrap();
        assert!(!compiled.lock_sql.contains("DROP TABLE"));
        assert!(!compiled.update_sql.contains("DROP TABLE"));
        assert!(compiled.lock_sql.contains("$1::text"));
    }

    #[test]
    fn generated_sql_is_fully_qualified_and_parameterized() {
        let fixture = fixture();
        let compiled = compile_statement(&fixture.intent, &fixture.configuration).unwrap();
        assert!(compiled.lock_sql.contains("FROM \"app\".\"demo_accounts\""));
        assert!(compiled.lock_sql.ends_with("FOR UPDATE"));
        assert!(
            compiled
                .update_sql
                .starts_with("UPDATE \"app\".\"demo_accounts\"")
        );
        assert!(!compiled.update_sql.contains("pending"));
        assert!(!compiled.update_sql.contains("reviewed"));
    }
}
