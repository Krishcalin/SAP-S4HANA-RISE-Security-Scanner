"""The CAP project auditor: the descriptor, the model, and the join between them.

Two parsers with two confidence levels, and the tests are shaped accordingly.

`xs-security.json` is JSON, so those tests assert exact values. The CDS model is
read lexically — there is no CDS compiler behind a stdlib-only offline product —
so those tests are mostly about the ONE direction the checks are written in: they
report what was positively found, and a construct the parser could not read is
declared unread rather than passed over.

The hardest bug found while building this is pinned below as
`test_a_service_does_not_inherit_the_previous_service_annotation`. The backward
walk that finds annotations above a declaration skipped over `}` as if it were a
bracket group, sailed out of the preceding service's body, and credited that
service's `@protocol: 'none'` to the next one. The result was an unprotected
service silently absent from the report, which is the exact failure this module
exists to prevent.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.cap_xsuaa import (CapXsuaaAuditor, CdsModel,      # noqa: E402
                               _split_reference, parse_cds_source,
                               strip_cds_comments,
                               _TOKEN_DEFAULT, _REFRESH_DEFAULT, _TOKEN_FLOOR)

FIXTURE = ROOT / "tests" / "fixtures" / "cap_project"


def _run(project=None, rows=None, **extra):
    data = dict(extra)
    if project is not None:
        data["cap_project_dir"] = str(project)
    if rows is not None:
        data["btp_role_collection_mappings"] = rows
    out = {}
    for finding in CapXsuaaAuditor(data, {}).run_all_checks():
        out.setdefault(finding["check_id"], []).append(finding)
    return out


def _project(tmp_path, descriptor=None, cds=None):
    """A minimal project on disk: an optional descriptor and one .cds file."""
    if descriptor is not None:
        (tmp_path / "xs-security.json").write_text(
            json.dumps(descriptor), encoding="utf-8")
    if cds is not None:
        srv = tmp_path / "srv"
        srv.mkdir(exist_ok=True)
        (srv / "service.cds").write_text(cds, encoding="utf-8")
    return tmp_path


def _model(source):
    model = CdsModel()
    parse_cds_source(source, "srv/x.cds", model)
    model.files = 1
    return model


# ═════════════════════════════════════════════════════════════════════════════
#  The numbers are SAP's
# ═════════════════════════════════════════════════════════════════════════════

def test_the_token_constants_match_the_subaccount_module_exactly():
    """BTP-TOK-* judges the subaccount policy and CAPX-TOK-001 judges the
    application's override of that same policy. Two different "SAP defaults"
    would put the two checks in disagreement about one setting."""
    from modules import btp_cloud_surface as btp
    assert _TOKEN_DEFAULT == btp._ACCESS_TOKEN_DEFAULT == 43200
    assert _REFRESH_DEFAULT == btp._REFRESH_TOKEN_DEFAULT == 604800
    assert _TOKEN_FLOOR == btp._TOKEN_VALIDITY_FLOOR == 1800


# ═════════════════════════════════════════════════════════════════════════════
#  Reference syntax — the three forms mean different things
# ═════════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("ref,expected", [
    ("$XSAPPNAME.Display", ("local", "Display")),
    ("$XSAPPNAME(application,business-partner).Create",
     ("foreign", "business-partner.Create")),
    ("uaa.user", ("external", "uaa.user")),
    ("", ("external", "")),
])
def test_a_scope_reference_is_split_by_its_documented_form(ref, expected):
    assert _split_reference(ref) == expected


def test_a_foreign_reference_is_never_reported_as_a_broken_link(tmp_path):
    """It names another application's descriptor, which is not in this project.
    Reporting it as missing would make every correctly integrated application a
    finding."""
    fired = _run(_project(tmp_path, {
        "xsappname": "app",
        "scopes": [{"name": "$XSAPPNAME.Read"}],
        "role-templates": [{"name": "R", "scope-references": [
            "$XSAPPNAME.Read", "$XSAPPNAME(application,other).Write", "uaa.user"]}],
    }))
    assert "CAPX-GRAPH-001" not in fired


def test_a_local_reference_with_no_definition_is_reported(tmp_path):
    fired = _run(_project(tmp_path, {
        "xsappname": "app",
        "scopes": [{"name": "$XSAPPNAME.Read"}],
        "role-templates": [{"name": "R", "scope-references": ["$XSAPPNAME.Typo"]}],
        "role-collections": [{"name": "C",
                              "role-template-references": ["$XSAPPNAME.Missing"]}],
    }))
    assert "CAPX-GRAPH-001" in fired
    items = fired["CAPX-GRAPH-001"][0]["affected_items"]
    assert len(items) == 2
    assert any("$XSAPPNAME.Typo" in i for i in items)
    assert any("$XSAPPNAME.Missing" in i for i in items)


# ═════════════════════════════════════════════════════════════════════════════
#  Descriptor checks
# ═════════════════════════════════════════════════════════════════════════════

def test_the_application_token_override_is_reported(tmp_path):
    """THE POINT OF THIS CHECK. BTP-TOK-001/002 state in every finding that they
    cannot see application overrides. SAP's own wording for the field is "These
    values override the values set for the subaccount"."""
    fired = _run(_project(tmp_path, {
        "xsappname": "app",
        "oauth2-configuration": {"token-validity": 86400}}))
    assert "CAPX-TOK-001" in fired
    finding = fired["CAPX-TOK-001"][0]
    assert finding["severity"] == "HIGH"
    assert "86400" in finding["affected_items"][0]
    assert finding["details"]["subaccount_check"] == "BTP-TOK-001/002"


def test_a_token_lifetime_within_the_baseline_is_not_reported(tmp_path):
    fired = _run(_project(tmp_path, {
        "xsappname": "app",
        "oauth2-configuration": {"token-validity": 1800,
                                 "refresh-token-validity": 43200}}))
    assert "CAPX-TOK-001" not in fired


def test_a_lifetime_beyond_the_documented_maximum_says_so(tmp_path):
    """SAP documents token-validity as ranging to 86400 seconds. Past that the
    service does not honour the value, so "longer than the default" would be the
    wrong thing to tell somebody."""
    fired = _run(_project(tmp_path, {
        "xsappname": "app",
        "oauth2-configuration": {"token-validity": 200000}}))
    assert "exceeds the documented maximum" in fired["CAPX-TOK-001"][0]["affected_items"][0]


@pytest.mark.parametrize("uri,flagged", [
    ("https://myapp.cfapps.eu10.hana.ondemand.com/callback", False),
    ("https://myapp.acme.com/callback/**", False),
    ("https://*.acme.com/callback", False),
    ("https://*.cfapps.eu10.hana.ondemand.com/callback", True),
    ("https://*.com/callback", True),
    ("http://myapp.acme.com/callback", True),
    ("https://*", True),
])
def test_redirect_uris_are_judged_on_the_host_not_the_path(tmp_path, uri, flagged):
    """SAP's own example of an acceptable pattern wildcards the PATH. The risk is
    in the host: a path wildcard under a host you own redirects to you, a host
    wildcard redirects to whoever registers the name."""
    fired = _run(_project(tmp_path, {
        "xsappname": "app",
        "oauth2-configuration": {"redirect-uris": [uri]}}))
    assert ("CAPX-URI-001" in fired) is flagged, uri


def test_a_wildcard_over_a_customer_domain_is_left_alone(tmp_path):
    """`https://*.mydomain.com/callback/**` is SAP's documented example of a
    supported pattern. Flagging it would make the check unusable in the estates
    that configured this correctly."""
    fired = _run(_project(tmp_path, {
        "xsappname": "app",
        "oauth2-configuration": {
            "redirect-uris": ["https://*.mydomain.com/callback/**"]}}))
    assert "CAPX-URI-001" not in fired


def test_value_required_false_is_reported_with_the_templates_it_affects(tmp_path):
    fired = _run(_project(tmp_path, {
        "xsappname": "app",
        "attributes": [{"name": "Country", "valueRequired": False},
                       {"name": "CostCenter", "valueRequired": True}],
        "role-templates": [
            {"name": "A", "attribute-references": ["Country"]},
            {"name": "B", "attribute-references": [{"name": "Country"}]},
            {"name": "C", "attribute-references": ["CostCenter"]}]}))
    item = fired["CAPX-ATTR-001"][0]["affected_items"][0]
    assert "Country" in item and "CostCenter" not in item
    # BOTH spellings of attribute-references are documented and both appear in
    # real descriptors; reading one would under-report which templates are hit.
    assert "A" in item and "B" in item


def test_accepted_authorities_is_reported_only_for_the_wildcard(tmp_path):
    named = _run(_project(tmp_path, {"xsappname": "a",
                                     "authorities": ["other.ForeignCall"]}))
    assert "CAPX-AUTH-001" not in named
    wild = _run(_project(tmp_path, {"xsappname": "a",
                                    "authorities": ["$ACCEPT_GRANTED_AUTHORITIES"]}))
    assert "CAPX-AUTH-001" in wild


def test_both_grant_properties_are_read(tmp_path):
    """`granted-apps` is the user scenario and `grant-as-authority-to-apps` is the
    client-credentials one. They are different risks and both are documented."""
    fired = _run(_project(tmp_path, {
        "xsappname": "app",
        "scopes": [{"name": "$XSAPPNAME.A",
                    "granted-apps": ["$XSAPPNAME(application,x)"]},
                   {"name": "$XSAPPNAME.B",
                    "grant-as-authority-to-apps": ["$XSAPPNAME(application,y)"]}]}))
    items = "\n".join(fired["CAPX-SCOPE-001"][0]["affected_items"])
    assert "user scenario" in items and "client credentials" in items


def test_instance_secret_is_reported_and_binding_secret_is_not(tmp_path):
    ok = _run(_project(tmp_path, {"xsappname": "a", "oauth2-configuration": {
        "credential-types": ["binding-secret", "x509"]}}))
    assert "CAPX-CRED-001" not in ok
    bad = _run(_project(tmp_path, {"xsappname": "a", "oauth2-configuration": {
        "credential-types": ["instance-secret"]}}))
    assert "CAPX-CRED-001" in bad


def test_shared_tenant_mode_is_reported_and_dedicated_is_not(tmp_path):
    assert "CAPX-TEN-001" not in _run(_project(tmp_path, {"xsappname": "a"}))
    assert "CAPX-TEN-001" not in _run(_project(
        tmp_path, {"xsappname": "a", "tenant-mode": "dedicated"}))
    assert "CAPX-TEN-001" in _run(_project(
        tmp_path, {"xsappname": "a", "tenant-mode": "shared"}))


def test_an_unparseable_descriptor_is_reported_rather_than_dropped(tmp_path):
    """A security descriptor that will not parse is the one most worth knowing
    about, and it is exactly the one a `try: except: pass` would lose."""
    (tmp_path / "xs-security.json").write_text("{ not json", encoding="utf-8")
    (tmp_path / "a.cds").write_text("service S { }", encoding="utf-8")
    fired = _run(tmp_path)
    assert "CAPX-COV-001" in fired
    assert fired["CAPX-COV-001"][0]["details"]["degrades_coverage"] is True
    assert any("xs-security.json" in i
               for i in fired["CAPX-COV-001"][0]["affected_items"])


# ═════════════════════════════════════════════════════════════════════════════
#  The CDS parser
# ═════════════════════════════════════════════════════════════════════════════

def test_a_service_does_not_inherit_the_previous_service_annotation():
    """THE BUG THIS TEST EXISTS FOR.

    The backward walk that collects annotations above a declaration treated `}`
    as a bracket group to skip, so it walked out of the preceding service's body
    and picked up ITS annotations. An unannotated service directly below a
    `@protocol: 'none'` service was therefore read as internal and vanished from
    CAPX-CDS-001 — a silent false negative in the one check that is supposed to
    catch the service nobody protected.
    """
    model = _model("""
        @protocol: 'none'
        service Internal { entity A as projection on db.A; }

        service Wide { entity B as projection on db.B; }
    """)
    assert "protocol" not in model.annotations_for("Wide")
    assert "protocol" in model.annotations_for("Internal")


def test_comment_stripping_preserves_offsets():
    """Every line number this module reports is computed from the stripped text.
    Deleting comments instead of blanking them would shift every offset after
    the first one, and a wrong line number is worse than none."""
    source = "line1\n/* two\n   lines */\nservice S { }\n"
    stripped = strip_cds_comments(source)
    assert len(stripped) == len(source)
    assert stripped.count("\n") == source.count("\n")
    assert "service S" in stripped and "two" not in stripped


def test_a_block_comment_opener_inside_a_string_does_not_blank_the_file():
    """The dangerous direction. A `/*` in a CDS literal used to start a comment
    that ran to the next `*/` or to end of file, blanking the annotations in
    between — and a service whose `@requires` has been blanked is reported by
    CAPX-CDS-001 as having no access control at all. A parser that under-reads
    must not be able to manufacture a HIGH finding."""
    model = _model("""
        service S {
          @restrict: [{ grant: 'READ', to: 'Auditor', where: (p = '/*') }]
          entity E as projection on db.E;
        }

        @requires: 'Admin'
        service T { entity F as projection on db.F; }
    """)
    assert "requires" in model.annotations_for("T"), "a literal blanked real source"
    assert {"Auditor", "Admin"} <= set(model.roles)


def test_a_url_in_a_string_is_not_treated_as_a_comment():
    """CDS `where` clauses carry URLs and paths. Treating `//` inside a literal
    as a comment would swallow the rest of a restriction and report the entity
    as unprotected."""
    model = _model("""
        service S {
          @restrict: [{ grant: 'READ', to: 'Auditor', where: (url = 'http://x//y') }]
          entity E as projection on db.E;
        }
    """)
    assert "Auditor" in model.roles
    assert not model.open_privileges


def test_an_annotation_in_a_separate_file_protects_the_service():
    """The common CAP layout puts entity rules in annotations.cds. A parser that
    only read inline annotations would report half the protected services."""
    model = CdsModel()
    parse_cds_source("service Reporting { entity R as projection on db.R; }",
                     "srv/s.cds", model)
    parse_cds_source("annotate Reporting with @(requires: 'FinanceAuditor');",
                     "srv/annotations.cds", model)
    model.files = 2
    assert "requires" in model.annotations_for("Reporting")
    assert "FinanceAuditor" in model.roles


def test_a_privilege_with_no_audience_is_found():
    """SAP: "the `any` pseudo-role applies for all users and is the default if no
    value is provided"."""
    model = _model("""
        service S {
          @restrict: [{ grant: 'READ' }, { grant: 'WRITE', to: 'Admin' }]
          entity E as projection on db.E;
        }
    """)
    assert len(model.open_privileges) == 1
    assert "Admin" in model.roles


def test_an_unterminated_restrict_is_recorded_not_guessed():
    model = _model("service S { @restrict: [{ grant: 'READ', to: 'A' } entity E; }")
    assert model.unresolved, "an unbalanced annotation was silently accepted"


def test_node_modules_is_not_read():
    """A CAP project routinely carries tens of thousands of dependency files,
    including other people's xs-security.json samples. Attributing a dependency's
    test fixture to the customer's application would be worse than missing it."""
    fired = _run(FIXTURE)
    items = "\n".join(fired["CAPX-CDS-001"][0]["affected_items"])
    assert "NotOurService" not in items
    assert "a-dependency-sample" not in json.dumps(fired["CAPX-TEN-001"][0])


# ═════════════════════════════════════════════════════════════════════════════
#  The join
# ═════════════════════════════════════════════════════════════════════════════

def test_the_chain_is_traced_from_scope_to_the_group_that_holds_it(tmp_path):
    """THE MODULE'S REASON TO EXIST. The descriptor knows what a collection
    grants and not who holds it; the subaccount export knows who holds it and not
    what it grants. Only together do they say that every federated user holds a
    named application scope."""
    project = _project(tmp_path, {
        "xsappname": "shop",
        "scopes": [{"name": "$XSAPPNAME.Admin"}],
        "role-templates": [{"name": "Admin",
                            "scope-references": ["$XSAPPNAME.Admin"]}],
        "role-collections": [{"name": "Shop_Admin",
                              "role-template-references": ["$XSAPPNAME.Admin"]}]})
    fired = _run(project, rows=[{"ROLE_COLLECTION": "Shop_Admin",
                                 "IDP_GROUP": "Default", "ROLE_NAMES": "Admin"}])
    finding = fired["CAPX-GRAPH-002"][0]
    assert finding["severity"] == "HIGH"
    item = finding["affected_items"][0]
    assert "Shop_Admin" in item and "Default" in item and "Admin" in item
    assert finding["details"]["also_reported_by"] == "S4AUTHZ-008"


def test_a_collection_mapped_to_a_named_group_is_not_birthright(tmp_path):
    project = _project(tmp_path, {
        "xsappname": "shop",
        "scopes": [{"name": "$XSAPPNAME.Admin"}],
        "role-templates": [{"name": "Admin", "scope-references": ["$XSAPPNAME.Admin"]}],
        "role-collections": [{"name": "Shop_Admin",
                              "role-template-references": ["$XSAPPNAME.Admin"]}]})
    fired = _run(project, rows=[{"ROLE_COLLECTION": "Shop_Admin",
                                 "IDP_GROUP": "SHOP_ADMINS", "ROLE_NAMES": "Admin"}])
    assert "CAPX-GRAPH-002" not in fired


def test_without_the_subaccount_export_the_chain_makes_no_claim(tmp_path):
    """Half a join is silence that looks like agreement, so it is not attempted."""
    project = _project(tmp_path, {
        "xsappname": "shop",
        "scopes": [{"name": "$XSAPPNAME.Admin"}],
        "role-templates": [{"name": "Admin", "scope-references": ["$XSAPPNAME.Admin"]}],
        "role-collections": [{"name": "Shop_Admin",
                              "role-template-references": ["$XSAPPNAME.Admin"]}]})
    fired = _run(project)
    assert "CAPX-GRAPH-002" not in fired
    assert "CAPX-GRAPH-003" not in fired


def test_a_template_a_cockpit_collection_delivers_is_not_called_orphaned(tmp_path):
    """A role collection assembled in the cockpit does not appear in any
    descriptor. Reporting its template as undeliverable would be a finding
    against a correctly configured project."""
    project = _project(tmp_path, {
        "xsappname": "shop",
        "scopes": [{"name": "$XSAPPNAME.Admin"}],
        "role-templates": [{"name": "Admin", "scope-references": ["$XSAPPNAME.Admin"]}]})
    fired = _run(project, rows=[{"ROLE_COLLECTION": "Assembled_By_Hand",
                                 "IDP_GROUP": "ADMINS", "ROLE_NAMES": "Admin"}])
    assert "CAPX-GRAPH-003" not in fired


def test_a_pseudo_role_is_never_reported_as_missing_from_the_descriptor(tmp_path):
    """`authenticated-user` is not a scope and cannot be in a descriptor.
    Comparing it against one would report every correctly-written service."""
    project = _project(
        tmp_path,
        {"xsappname": "app", "role-templates": [{"name": "Admin"}]},
        "@(requires: 'authenticated-user')\nservice S { entity E as projection on db.E; }\n")
    fired = _run(project)
    assert "CAPX-CDS-003" not in fired


def test_a_role_the_descriptor_does_not_grant_is_reported(tmp_path):
    project = _project(
        tmp_path,
        {"xsappname": "app", "role-templates": [{"name": "Admin"}]},
        "@(requires: 'FinanceAuditor')\nservice S { entity E as projection on db.E; }\n")
    finding = _run(project)["CAPX-CDS-003"][0]
    assert "FinanceAuditor" in finding["affected_items"][0]
    assert finding["severity"] == "MEDIUM"


def test_a_role_granted_by_a_scope_rather_than_a_template_counts(tmp_path):
    """`cds compile --to xsuaa` writes both; a descriptor carrying only the scope
    still grants the role, and reporting it as missing would be wrong."""
    project = _project(
        tmp_path,
        {"xsappname": "app", "scopes": [{"name": "$XSAPPNAME.Auditor"}]},
        "@(requires: 'Auditor')\nservice S { entity E as projection on db.E; }\n")
    assert "CAPX-CDS-003" not in _run(project)


# ═════════════════════════════════════════════════════════════════════════════
#  Absent, unreadable, and half-supplied
# ═════════════════════════════════════════════════════════════════════════════

def test_no_project_supplied_is_silent():
    """An absent optional input is not degraded coverage. Conflating the two
    would arm the gate on every scan that omits any optional input."""
    assert _run() == {}


def test_a_path_that_is_not_a_directory_is_a_finding(tmp_path):
    """Asked to look, could not. An empty result here is indistinguishable from
    a project with nothing wrong in it."""
    fired = _run(tmp_path / "does-not-exist")
    assert "CAPX-COV-001" in fired
    assert fired["CAPX-COV-001"][0]["details"]["reason"] == "not_a_directory"
    assert fired["CAPX-COV-001"][0]["details"]["degrades_coverage"] is True


def test_an_empty_directory_is_a_finding(tmp_path):
    fired = _run(tmp_path)
    assert fired["CAPX-COV-001"][0]["details"]["reason"] == "nothing_to_read"


def test_a_model_with_no_descriptor_degrades_coverage(tmp_path):
    """Half of this module's checks are joins, and a join with one side missing
    produces silence that looks exactly like agreement."""
    fired = _run(_project(tmp_path, cds="service S { entity E as projection on db.E; }"))
    assert "CAPX-COV-001" in fired
    assert any("no xs-security.json" in i
               for i in fired["CAPX-COV-001"][0]["affected_items"])


def test_a_descriptor_with_no_model_degrades_coverage(tmp_path):
    fired = _run(_project(tmp_path, {"xsappname": "app"}))
    assert any("no .cds file" in i
               for i in fired["CAPX-COV-001"][0]["affected_items"])


def test_a_clean_project_produces_no_coverage_finding(tmp_path):
    fired = _run(_project(
        tmp_path,
        {"xsappname": "app", "role-templates": [{"name": "Admin"}]},
        "@(requires: 'Admin')\nservice S { entity E as projection on db.E; }\n"))
    assert "CAPX-COV-001" not in fired
    assert fired == {}, "a correctly configured project raised something"


# ═════════════════════════════════════════════════════════════════════════════
#  End to end on the shipped fixture
# ═════════════════════════════════════════════════════════════════════════════

@pytest.fixture(scope="module")
def shop():
    return _run(FIXTURE, rows=[
        {"ROLE_COLLECTION": "Bookshop_Viewer", "IDP_GROUP": "Default",
         "ROLE_NAMES": "Viewer"},
        {"ROLE_COLLECTION": "Bookshop_Admin", "IDP_GROUP": "BOOKSHOP_ADMINS",
         "ROLE_NAMES": "Admin"}])


def test_every_check_in_this_module_fires_on_the_fixture(shop):
    """The fixture is a realistic CAP project carrying one instance of each
    defect. A check with no fixture is a check nobody has seen run."""
    expected = {
        "CAPX-GRAPH-001", "CAPX-GRAPH-002", "CAPX-GRAPH-003", "CAPX-SCOPE-001",
        "CAPX-AUTH-001", "CAPX-ATTR-001", "CAPX-TOK-001", "CAPX-URI-001",
        "CAPX-CRED-001", "CAPX-TEN-001", "CAPX-CDS-001", "CAPX-CDS-002",
        "CAPX-CDS-003", "CAPX-CDS-004", "CAPX-CDS-005",
    }
    assert expected == set(shop), sorted(expected ^ set(shop))


def test_only_the_genuinely_unprotected_service_is_named(shop):
    """Five services: two annotated inline, one via annotations.cds, one marked
    @protocol:'none', and one with nothing. Only the last may be named."""
    items = shop["CAPX-CDS-001"][0]["affected_items"]
    assert len(items) == 1 and items[0].startswith("AdminService"), items


def test_the_fixture_project_is_read_without_unresolved_constructs(shop):
    """The parser must be able to read a realistic project completely. If it
    cannot, the CDS findings above are being made against a partial view."""
    assert "CAPX-COV-001" not in shop


# ═════════════════════════════════════════════════════════════════════════════
#  CAPX-CDS-004 — the $expand reach, and CAPX-CDS-005 — the property surface
# ═════════════════════════════════════════════════════════════════════════════

#: SAP's own worked example from "Control Exposure of Associations and
#: Compositions", kept in its documented shape because the whole point of these
#: tests is that this module agrees with the guide about the case the guide
#: itself calls a security issue.
SAP_EXAMPLE = """namespace db;

entity Employees : cuid {
  name     : String(128);
  team     : Association to Teams;
  contract : Composition of Contracts;
}

entity Contracts @(requires:'Manager') : cuid {
  @PersonalData.IsPotentiallySensitive
  salary : Decimal;
}

entity Teams : cuid {
  members : Composition of many Employees on members.team = $self;
}

service ManageTeamsService @(requires:'Manager') {
  entity Teams as projection on db.Teams;
}

service BrowseEmployeesService @(requires:'Employee') {
  @readonly entity Teams as projection on db.Teams;
}
"""

#: The same model after applying the fix the guide prescribes: "introduce a new
#: service entity BrowseEmployeesService.Employees that removes the navigation
#: to Contracts from the projection".
SAP_EXAMPLE_FIXED = SAP_EXAMPLE.replace(
    """service BrowseEmployeesService @(requires:'Employee') {
  @readonly entity Teams as projection on db.Teams;
}""",
    """service BrowseEmployeesService @(requires:'Employee') {
  @readonly entity Employees as projection on db.Employees excluding { contract };
  @readonly entity Teams as projection on db.Teams;
}""")


def _expand(tmp_path, source):
    return _run(_project(tmp_path, cds=source)).get("CAPX-CDS-004", [])


def test_the_documented_expand_path_is_found(tmp_path):
    """SAP: "only the target entity BrowseEmployeesService.Teams has to pass the
    authorization check in the generic handler, and not the associated
    entities". The finding must name that entity, that path and that target."""
    findings = _expand(tmp_path, SAP_EXAMPLE)
    assert len(findings) == 1
    items = findings[0]["affected_items"]
    assert len(items) == 1, items
    assert items[0].startswith("BrowseEmployeesService.Teams")
    assert "$expand=members($expand=contract)" in items[0]
    assert "db.Contracts" in items[0] and "Manager" in items[0]


def test_the_service_that_already_requires_the_role_is_not_reported(tmp_path):
    """`ManageTeamsService` requires 'Manager' and so does `Contracts`. The guide
    describes that navigation as the intended one. A check that reported both
    services would be reporting the model's shape rather than a defect."""
    items = _expand(tmp_path, SAP_EXAMPLE)[0]["affected_items"]
    assert not any(i.startswith("ManageTeamsService") for i in items), items


def test_the_fix_the_guide_prescribes_silences_the_finding(tmp_path):
    """The single most damaging thing this check could do is keep firing after
    the developer applied SAP's own remedy. That remedy works through
    auto-redirection — navigation from `Teams.members` lands on the reduced
    projection — so this is really a test that redirection is modelled."""
    assert _expand(tmp_path, SAP_EXAMPLE_FIXED) == []


def test_an_unrestricted_target_is_not_reported(tmp_path):
    """The subject is a restriction that will not be enforced. An entity with no
    restriction has nothing to fail to enforce, and reporting every navigation
    in the model would bury the ones that matter."""
    source = SAP_EXAMPLE.replace("entity Contracts @(requires:'Manager') : cuid {",
                                 "entity Contracts : cuid {")
    assert _expand(tmp_path, source) == []


def test_a_pseudo_role_on_the_target_is_not_a_privilege_gap(tmp_path):
    """`authenticated-user` is held by everyone who reached the service at all,
    so demanding it downstream adds nothing the caller has not proved. Treating
    it as a gap would report every model that annotates defensively."""
    source = SAP_EXAMPLE.replace("entity Contracts @(requires:'Manager')",
                                 "entity Contracts @(requires:'authenticated-user')")
    assert _expand(tmp_path, source) == []


def test_the_hop_kind_is_recorded_because_the_runtimes_differ(tmp_path):
    """Composition hops are unenforced on both runtimes; association hops are
    enforced by CAP Java 4.0's deep authorization. The finding has to carry
    which it saw, or a Java reader cannot tell how much of it applies."""
    details = _expand(tmp_path, SAP_EXAMPLE)[0]["details"]
    assert details["composition_hops"] is True
    assert details["runtime"] == "unknown"     # no package.json, no pom.xml


def test_the_runtime_is_read_from_the_project_not_assumed(tmp_path):
    from modules.cap_xsuaa import detect_runtime
    assert detect_runtime(tmp_path) == "unknown"
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"@sap/cds": "^8"}}), encoding="utf-8")
    assert detect_runtime(tmp_path) == "node"
    (tmp_path / "pom.xml").write_text("<project/>", encoding="utf-8")
    assert detect_runtime(tmp_path) == "both"


def test_a_cycle_in_the_model_terminates(tmp_path):
    """`Teams -> members -> team -> members` is a legal CAP model, and this one
    contains it. A walk that was cycle-safe on the path rather than on the node
    would not return at all."""
    source = SAP_EXAMPLE.replace("entity Teams : cuid {",
                                 "entity Teams @(requires:'Lead') : cuid {")
    assert _expand(tmp_path, source)          # it terminated, and it found something


def test_a_navigation_to_an_entity_this_scan_never_saw_is_declared_unread():
    """The target may live in a reuse package the checkout did not include.
    Silence there would be indistinguishable from a resolved, harmless hop."""
    from modules.cap_xsuaa import navigation_reach
    model = _model("namespace db;\n"
                   "entity Orders : cuid { ref : Association to external.Ledger; }\n"
                   "service S { entity Orders as projection on db.Orders; }")
    assert navigation_reach(model, "S.Orders") == []
    assert any("external.Ledger" in note for note in model.unresolved)


def test_property_exposure_rests_on_the_models_own_annotation(tmp_path):
    """CAP supports no `@requires`/`@restrict` at element level, so the
    projection is the only control there is. The finding names the element the
    MODEL marked — never one this check thought looked sensitive."""
    source = SAP_EXAMPLE + ("\nservice PayrollService @(requires:'Manager') {\n"
                            "  entity Contracts as projection on db.Contracts;\n}\n")
    findings = _run(_project(tmp_path, cds=source))["CAPX-CDS-005"]
    items = findings[0]["affected_items"]
    assert len(items) == 1, items
    assert items[0].startswith("PayrollService.Contracts.salary")
    assert "@PersonalData.IsPotentiallySensitive" in items[0]
    assert findings[0]["details"]["basis"] == "model_annotation"


def test_an_unannotated_column_is_never_guessed_at(tmp_path):
    """`salary` is about as suggestive a column name as exists. Without the
    model's annotation it must produce nothing: a name is not evidence."""
    source = (SAP_EXAMPLE.replace("  @PersonalData.IsPotentiallySensitive\n", "")
              + "\nservice PayrollService @(requires:'Manager') {\n"
                "  entity Contracts as projection on db.Contracts;\n}\n")
    assert "CAPX-CDS-005" not in _run(_project(tmp_path, cds=source))


def test_excluding_the_element_settles_it(tmp_path):
    source = SAP_EXAMPLE + (
        "\nservice PayrollService @(requires:'Manager') {\n"
        "  entity Contracts as projection on db.Contracts excluding { salary };\n}\n")
    assert "CAPX-CDS-005" not in _run(_project(tmp_path, cds=source))


def test_the_new_findings_carry_the_standards_mapping(shop):
    """CWE-863 and CWE-359 both reach A01 through the published lists rather
    than through this module's opinion."""
    finding = shop["CAPX-CDS-004"][0]
    assert finding["details"]["cwe"] == "CWE-863"
    assert finding["owasp"]["owasp_top10"] == "A01"
    assert finding["owasp"]["basis"] == "cwe"
    assert shop["CAPX-CDS-005"][0]["owasp"]["owasp_top10"] == "A01"


def test_the_fixture_reports_the_composition_hop_the_reporting_service_opens(shop):
    """A FinanceAuditor may read orders. `Payments` says only Treasury may read
    bank details. `Orders?$expand=payment` returns them anyway."""
    items = shop["CAPX-CDS-004"][0]["affected_items"]
    hit = [i for i in items if i.startswith("ReportingService.Orders")]
    assert len(hit) == 1, items
    assert "FinanceAuditor" in hit[0] and "Treasury" in hit[0]
    assert "$expand=payment" in hit[0]
