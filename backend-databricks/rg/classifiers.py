"""Classifier library and scoring.

A classifier describes one data element (EMAIL, PHONE, FIRST_NAME ...) and looks for it two ways:
  * name evidence     - does the column NAME look like it (regex on the column name)?
  * content evidence  - do the VALUES look like it (regex, dictionary, date-shape, Luhn, IBAN ...)?

confidence = name_weight * name_hit + content_weight * content_score

The weights say how much to trust each kind of evidence. A strong pattern such as an email leans on
content; an ambiguous one such as a date of birth leans on the column name.
"""
from __future__ import annotations

import datetime as dt
import re
import statistics
from typing import Any

AUTO_THRESHOLD = 0.80      # classified without review
REVIEW_THRESHOLD = 0.50    # needs a steward decision
LOW_THRESHOLD = 0.30       # recorded as a low-confidence candidate, ignored by policies

# --------------------------------------------------------------------------- dictionaries (general, not tuned to the data)
FIRST_NAMES = set("""
adam adrian alan albert alex alexander alice amanda amy andrea andreas andrew angela anna anne anthony arthur barbara
ben benjamin bernd beth betty bianca brian carl carla carol caroline catherine charles charlotte chloe chris christian
christina christoph claire claudia daniel david deborah dennis diana diane dieter donald donna dorothy edward elena
elisabeth elizabeth ella emil emily emma eric erik eva felix florian frank franz fred gabriel george gerhard gisela
grace hannah hans harry heather heike heinrich helen helga henry holger ian ingrid isabella jack jacob james jan jane
janet jason jennifer jeremy jessica joan joe johann johanna john jonas jonathan joseph joshua judith julia julian
karen karin karl katharina katherine kathleen kevin klaus kurt laura lea lena leon leonie linda lisa louis lucas
lukas maria marie marc marcus margaret mark martin mary matthew max megan melissa michael michelle monika nancy
natalie nicholas nicole noah oliver olivia oscar pamela patricia patrick paul paula peter petra philip rachel
rebecca richard robert roger ronald rose ruth ryan sabine samuel sandra sara sarah sebastian simon sophia sophie
stefan stephanie stephen steven susan susanne sven tanja teresa thomas timothy tobias tom ulrich ursula vanessa
victoria vincent walter wendy werner william wolfgang yvonne
""".split())

LAST_NAMES = set("""
adams allen anderson bailey baker bauer becker bell bennett brooks brown bruns campbell carter clark collins cook
cooper cox davis edwards evans fischer flores foster garcia gonzalez gray green hall harris hartmann hill howard
hughes jackson james jansen jenkins johnson jones keller kelly king klein koch krause kruger lang lee lewis lopez
martin martinez meyer miller mitchell moore morgan morris muller murphy nelson neumann nguyen parker patel perez
perry peters phillips powell price reed richter rivera roberts robinson rodriguez rogers ross russell sanchez
schmidt schneider scholz schulz schwarz scott simmons smith stewart taylor thomas thompson torres turner wagner
walker ward watson weber wells white williams wilson wolf wood wright young zimmermann
""".split())

_EMAIL = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}$")
_PHONE_INTL = re.compile(r"^\+\d{1,3}[\s.\-]?\(?\d{1,4}\)?([\s.\-]?\d{2,}){1,4}$")
_PHONE_LOCAL = re.compile(r"^\(?\d{2,5}\)?[\s.\-]\d{3,}([\s.\-]\d{2,})*$")
_IBAN = re.compile(r"^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$")


# --------------------------------------------------------------------------- built-in library (seeded into RG_CLASSIFIER)
def _c(code, name, category, applies_to, name_pattern, method, content_pattern=None, name_w=0.35, content_w=0.65,
       pii_class="DIRECT", description="", min_match_ratio=None, scope_country=None, scope_region=None):
    """pii_class: DIRECT identifier | IDENTIFIER (pseudonymous business id) | QUASI (identifies in combination) |
    SENSITIVE (special-category data). min_match_ratio: for sparse evidence, the share of matching values that
    already counts as full content evidence (e.g. 0.15 = 'a sixth of the rows mention a medical term')."""
    return dict(code=code, name=name, category=category, applies_to=applies_to, name_pattern=name_pattern,
                content_method=method, content_pattern=content_pattern, name_weight=name_w,
                content_weight=content_w, pii_class=pii_class, description=description,
                min_match_ratio=min_match_ratio, scope_country=scope_country, scope_region=scope_region)


BUILTIN_CLASSIFIERS = [
    _c("EMAIL", "Email address", "PII", "STRING", r"E?_?MAIL", "REGEX", None, 0.20, 0.80,
       description="RFC-style email pattern"),
    _c("PHONE", "Phone number", "PII", "STRING", r"PHONE|MOBILE|TEL(EPHONE)?($|_)|FAX", "PHONE", None, 0.35, 0.65,
       description="International (+CC ...) or separated local numbers"),
    _c("FIRST_NAME", "First / given name", "PII", "STRING", r"(^|_)(FIRST|GIVEN|FORE)_?NAME", "DICT_FIRST", None, 0.35,
       0.65, description="Value found in a common first-name dictionary"),
    _c("LAST_NAME", "Last / family name", "PII", "STRING", r"(^|_)(LAST|SUR|FAMILY)_?NAME", "DICT_LAST", None, 0.35,
       0.65, description="Value found in a common surname dictionary"),
    _c("FULL_NAME", "Full person name", "PII", "STRING",
       r"^(?!.*(FIRST|LAST|SUR|GIVEN|FAMILY|FORE)).*(^|_)NAME$", "FULL_NAME", None, 0.35, 0.65,
       description="Two or more words: known first name followed by a surname"),
    _c("DATE_OF_BIRTH", "Date of birth", "PII", "DATE", r"BIRTH|DOB|BORN", "DOB", None, 0.60, 0.40,
       pii_class="QUASI", description="Date column spread across decades with plausible birth years"),
    # Deliberately "house number first" only (e.g. "221B Baker Street, London") - an earlier version also
    # matched "word(s) then number" for European house-number-last addresses ("Hauptstrasse 12"), but that
    # shape is indistinguishable from ordinary English cross-references ("See Section 5", "Chapter 12",
    # "Figure 3") with no column-name evidence to weigh it against in the free-text document sweep
    # (docscan.py) - and REGEX goes straight to AUTO/95% confidence there with no further review gate, so
    # a false match isn't just a bad Finding, it gets redacted. Narrower recall, much lower false-positive
    # rate; see _c()'s content_weight note above for why that trade favours precision here.
    _c("STREET_ADDRESS", "Street address", "PII", "STRING", r"ADDR(ESS)?|STREET", "REGEX",
       r"^\d{1,5}[A-Za-z]?[ \t]+[A-Z][a-zA-Z.'\-]*(?:[ \t]+[A-Z][a-zA-Z.'\-]*){1,4}(?:,[ \t]*[A-Z][a-zA-Z.'\-]*)?$",
       0.60, 0.40, description="House number followed by two or more capitalised words (street, optionally + city)"),
    _c("POSTAL_CODE", "Postal / ZIP code", "PII", "STRING", r"POSTAL|ZIP|POST_?CODE", "REGEX",
       r"^(\d{4,5}(-\d{4})?|[A-Z]{1,2}\d[A-Z\d]? ?\d[A-Z]{2})$", 0.75, 0.25, pii_class="QUASI",
       description="Quasi-identifier: identifies a person in combination with other fields"),
    _c("GENDER", "Gender", "PII", "STRING", r"GENDER|SEX", "ENUM", "M,F,X,MALE,FEMALE,U", 0.75, 0.25,
       pii_class="QUASI", description="Quasi-identifier"),
    _c("LICENSE_ID", "Professional / licence ID", "PII", "STRING", r"LICEN[CS]E|PASSPORT|NATIONAL_?ID|SSN|TAX_?ID",
       "REGEX", r"^[A-Z]{2,4}[\-/ ]?\d{4,10}$", 0.72, 0.28,
       description="Identifier assigned to an individual"),
    _c("NATIONAL_ID_US", "US Social Security number", "PII", "STRING", r"SSN|SOCIAL", "REGEX",
       r"^\d{3}-\d{2}-\d{4}$", 0.20, 0.80, description="NNN-NN-NNNN", scope_country="US"),
    _c("IBAN", "IBAN bank account", "FINANCIAL", "STRING", r"IBAN|ACCOUNT", "IBAN", None, 0.20, 0.80,
       description="ISO 13616 with mod-97 check"),
    _c("CREDIT_CARD", "Payment card number", "FINANCIAL", "STRING", r"CARD|(^|_)PAN($|_)", "LUHN", None, 0.20, 0.80,
       description="13-19 digits passing the Luhn check"),
    _c("ANNUAL_INCOME", "Income / salary", "FINANCIAL", "NUMBER", r"INCOME|SALARY|WAGE|EARNINGS|REMUNERATION", "NUMERIC", None, 0.80, 0.20,
       pii_class="QUASI", description="Personal financial attribute"),

    # ---- quasi-identifiers and pseudonymous IDs: what remains identifying after names and contacts are removed
    _c("CUSTOMER_NUMBER", "Customer / member number", "PII", "STRING",
       r"(CUSTOMER|CLIENT|MEMBER|POLICYHOLDER)_?(NO|NUM|NUMBER)($|_)", "REGEX", r"^[A-Z]{2}\d{6,10}$", 0.80, 0.20,
       pii_class="IDENTIFIER", description="Business identifier that points at one person"),
    _c("CITY", "City / town", "PII", "STRING", r"(^|_)(CITY|TOWN)($|_)", "NONE", None, 0.85, 0.0,
       pii_class="QUASI", description="Name evidence only. Ignored in tables that are not about people"),
    _c("REGION", "State / region", "PII", "STRING", r"(^|_)(STATE|PROVINCE|COUNTY|REGION)($|_)", "NONE", None, 0.85, 0.0,
       pii_class="QUASI", description="Coarse location. Ignored in tables that are not about people"),
    _c("OCCUPATION", "Occupation", "PII", "STRING", r"OCCUPATION|PROFESSION|JOB_?TITLE|EMPLOYER", "NONE", None, 0.85, 0.0,
       pii_class="QUASI", description="Fine-grained attribute that narrows down who a person is"),
    _c("MARITAL_STATUS", "Marital status", "PII", "STRING", r"MARITAL|CIVIL_?STATUS", "ENUM",
       "SINGLE,MARRIED,DIVORCED,WIDOWED,SEPARATED,PARTNERED", 0.50, 0.50, pii_class="QUASI",
       description="Low-cardinality personal attribute"),

    # ---- health / special-category data (GDPR Art. 9): a second domain, found by keyword evidence
    _c("HEALTH_CLAIM", "Health / medical claim information", "PHI", "STRING",
       r"DIAGNOS|ICD|MEDICAL|TREATMENT|CONDITION|ILLNESS|CLAIM_?TYPE|DESCRIPTION", "KEYWORD",
       "dental,hospital,outpatient,inpatient,surgery,surgical,medical,illness,disability,diagnos,treatment,therapy,"
       "prescription,medication,clinic,cancer,diabetes,maternity,rehabilitation", 0.15, 0.85,
       pii_class="SENSITIVE", min_match_ratio=0.15,
       description="Medical terms in claim types, descriptions or payee types. Sparse: 15% of rows is full evidence"),

    # ---- marketing and consent: a domain that is about permissions and profiling, not identity. Found mostly by column
    # name, because a Y/N flag looks the same whatever it means.
    _c("MARKETING_CONSENT", "Marketing consent / opt-out flag", "MARKETING", "ANY",
       r"CONSENT|OPT_?(IN|OUT)|(^|_)(MARKETING|MKT)_?(FLAG|PREF|OPT|IND)|DO_?NOT_?(CONTACT|CALL|MAIL|EMAIL|SELL)|UNSUBSCRIB|NEWSLETTER|(^|_)DNC($|_)",
       "ENUM", "Y,N,YES,NO,TRUE,FALSE,1,0,OPT_IN,OPT_OUT,OPTED_IN,OPTED_OUT,GRANTED,WITHDRAWN,PENDING", 0.75, 0.25,
       pii_class="QUASI", description="Consent or opt-out flag. Text or number column with a few distinct values"),
    _c("CONTACT_PREFERENCE", "Contact channel preference", "MARKETING", "STRING",
       r"(PREFERRED|CONTACT|COMM(UNICATION)?)_?(CHANNEL|METHOD|MODE|PREF)", "ENUM",
       "EMAIL,SMS,PHONE,POST,MAIL,APP,PUSH,WHATSAPP,LETTER,NONE", 0.60, 0.40, pii_class="QUASI",
       description="How a customer agreed to be contacted"),
    _c("MARKETING_SEGMENT", "Marketing segment / propensity", "MARKETING", "STRING",
       r"^(?!.*(RISK|UNDERWRIT|CREDIT)).*(SEGMENT|PERSONA|PROPENSITY|LIFETIME_?VALUE|(^|_)(CLV|LTV)($|_)|CHURN|LEAD_?SCORE|NEXT_?BEST|AFFINITY|UPSELL|CROSS_?SELL)",
       "NONE", None, 0.85, 0.0, pii_class="QUASI",
       description="Profiling output about a customer. Name evidence only. Risk and underwriting segments are excluded"),
    _c("CAMPAIGN_SOURCE", "Campaign / lead source", "MARKETING", "STRING",
       r"CAMPAIGN|LEAD_?SOURCE|UTM_|REFERRAL_?CODE|PROMO(TION)?_?CODE|COUPON|ACQUISITION_?(CHANNEL|SOURCE)", "NONE", None,
       0.85, 0.0, pii_class="QUASI", description="Which campaign or channel brought a customer in. Name evidence only"),

    # ---- legal: litigation and legal-hold material. Not personal data as such; the concern is preserving it, or
    # keeping it from being deleted while a matter is open.
    _c("LEGAL_HOLD_FLAG", "Legal hold / litigation hold flag", "LEGAL", "ANY",
       r"LEGAL_?HOLD|LITIGATION_?HOLD|(^|_)HOLD_?(FLAG|IND|STATUS)|PRESERVATION", "ENUM",
       "Y,N,YES,NO,TRUE,FALSE,1,0,ACTIVE,RELEASED,HELD,NONE", 0.75, 0.25, pii_class="SENSITIVE",
       description="Marks a record as held. Records under a hold must not be erased or expired"),
    _c("LITIGATION_REF", "Litigation / legal matter reference", "LEGAL", "STRING",
       r"LITIGATION|LAWSUIT|COURT|LEGAL_?(CASE|REF|MATTER|ACTION|STATUS|COUNSEL)|SUBPOENA|ATTORNEY|SOLICITOR|LAWYER|ARBITRATION|TRIBUNAL|DISPUTE_?(REF|ID|STATUS)",
       "NONE", None, 0.85, 0.0, pii_class="SENSITIVE",
       description="Column that references a lawsuit, court, counsel or dispute. Name evidence only"),
    _c("LEGAL_TEXT", "Legal / litigation wording in free text", "LEGAL", "STRING",
       r"DESCRIPTION|REMARK|NOTE|COMMENT|MEMO|NARRATIVE|DETAIL", "KEYWORD",
       "litigat,lawsuit,subpoena,arbitration,tribunal,plaintiff,defendant,injunction",
       0.25, 0.75, pii_class="SENSITIVE", min_match_ratio=0.05,
       description="Litigation terms inside notes and descriptions. Needs a text-like column name to reach AUTO. Sparse: 5% of rows is full evidence. Job titles such as lawyer are deliberately not matched"),

    # ---- country packs: national identifiers. They are only applied when the country is active for the organisation.
    _c("SG_NRIC", "Singapore NRIC / FIN", "PII", "STRING", r"NRIC|(^|_)FIN($|_)|(^|_)IC_?NO", "REGEX", r"^[STFGM]\d{7}[A-Z]$",
       0.35, 0.65, description="1 letter, 7 digits, 1 letter", scope_country="SG"),
    _c("IN_AADHAAR", "India Aadhaar number", "PII", "STRING", r"AADHA?A?R|(^|_)UID(AI)?($|_)", "REGEX",
       r"^[2-9]\d{3}\s?\d{4}\s?\d{4}$", 0.35, 0.65, description="12 digits, may be grouped in fours", scope_country="IN"),
    _c("IN_PAN", "India PAN", "PII", "STRING", r"(^|_)PAN($|_)|PAN_?(NO|NUM)|PERMANENT_ACCOUNT", "REGEX", r"^[A-Z]{5}\d{4}[A-Z]$",
       0.30, 0.70, description="5 letters, 4 digits, 1 letter", scope_country="IN"),
    _c("GB_NINO", "UK National Insurance number", "PII", "STRING", r"NINO|NATIONAL_?INS", "REGEX",
       r"^[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]$", 0.30, 0.70,
       description="2 letters, 6 digits, 1 letter", scope_country="GB"),
    _c("DE_TAX_ID", "German tax ID (Steuer-ID)", "PII", "STRING", r"STEUER|TAX_?ID|IDNR", "REGEX", r"^\d{11}$", 0.70, 0.30,
       description="11 digits. Ambiguous on its own, so the column name carries most of the weight", scope_country="DE"),
    _c("FR_NIR", "French social security number (NIR)", "PII", "STRING", r"(^|_)NIR($|_)|INSEE|SECU|SOCIAL_?SEC", "REGEX",
       r"^[12]\s?\d{2}\s?(0[1-9]|1[0-2])\s?\d{2}\s?\d{3}\s?\d{3}\s?(\d{2})?$", 0.40, 0.60,
       description="13 digits plus an optional 2-digit key", scope_country="FR"),
    _c("ES_DNI", "Spanish DNI / NIE", "PII", "STRING", r"(^|_)(DNI|NIE|NIF)($|_)", "REGEX", r"^\d{8}[A-Z]$|^[XYZ]\d{7}[A-Z]$",
       0.50, 0.50, description="8 digits and a letter, or X/Y/Z + 7 digits + letter", scope_country="ES"),
    _c("IT_CODICE_FISCALE", "Italian codice fiscale", "PII", "STRING", r"CODICE_?FISCALE|(^|_)CF($|_)", "REGEX",
       r"^[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]$", 0.20, 0.80, description="16 characters", scope_country="IT"),
    _c("BR_CPF", "Brazil CPF", "PII", "STRING", r"(^|_)CPF($|_)", "CPF", None, 0.30, 0.70,
       description="11 digits with two check digits", scope_country="BR"),
    _c("CA_SIN", "Canada Social Insurance Number", "PII", "STRING", r"(^|_)SIN($|_)|SOCIAL_?INSURANCE", "REGEX_LUHN",
       r"^\d{3}[- ]?\d{3}[- ]?\d{3}$", 0.30, 0.70, description="9 digits passing the Luhn check", scope_country="CA"),
    _c("CN_RESIDENT_ID", "China resident ID", "PII", "STRING", r"ID_?CARD|RESIDENT_?ID|SHENFENZHENG", "CN_ID", None, 0.30, 0.70,
       description="18 characters with an ISO 7064 check character", scope_country="CN"),
    _c("JP_MY_NUMBER", "Japan My Number", "PII", "STRING", r"MY_?NUMBER|MYNUMBER|KOJIN", "REGEX", r"^\d{12}$", 0.75, 0.25,
       description="12 digits. Ambiguous on its own, so the column name carries most of the weight", scope_country="JP"),
    _c("KR_RRN", "South Korea resident registration number", "PII", "STRING", r"(^|_)RRN($|_)|RESIDENT_?REG", "REGEX",
       r"^\d{6}-?[1-4]\d{6}$", 0.30, 0.70, description="6 digits, a dash and 7 digits", scope_country="KR"),
    _c("AU_TFN", "Australia tax file number", "PII", "STRING", r"(^|_)TFN($|_)|TAX_?FILE", "REGEX", r"^\d{3}\s?\d{3}\s?\d{2,3}$",
       0.70, 0.30, description="8 or 9 digits. Ambiguous on its own", scope_country="AU"),
    _c("ZA_ID", "South Africa ID number", "PII", "STRING", r"SA_?ID|ID_?NUMBER|IDENTITY_?NO", "REGEX", r"^\d{13}$", 0.70, 0.30,
       description="13 digits. Ambiguous on its own", scope_country="ZA"),

    # ---- regional pack
    _c("EU_VAT_ID", "EU VAT registration number", "FINANCIAL", "STRING", r"(^|_)VAT($|_)|VAT_?(ID|NO|NUM)", "REGEX",
       r"^(AT|BE|BG|CY|CZ|DE|DK|EE|EL|ES|FI|FR|HR|HU|IE|IT|LT|LU|LV|MT|NL|PL|PT|RO|SE|SI|SK)[0-9A-Z]{8,12}$", 0.40, 0.60,
       pii_class="IDENTIFIER", description="Identifies a business, and a sole trader personally", scope_region="EUROPE"),
]


# --------------------------------------------------------------------------- content evaluators
def _luhn(s: str) -> bool:
    digits = [int(c) for c in s if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d = d * 2 - 9 if d * 2 > 9 else d * 2
        total += d
    return total % 10 == 0


def _luhn_valid(digits: str) -> bool:
    ds = [int(c) for c in digits if c.isdigit()]
    if len(ds) < 8:
        return False
    total = 0
    for i, d in enumerate(reversed(ds)):
        if i % 2:
            d = d * 2 - 9 if d * 2 > 9 else d * 2
        total += d
    return total % 10 == 0


def _cpf_ok(s: str) -> bool:
    d = [int(c) for c in s if c.isdigit()]
    if len(d) != 11 or len(set(d)) == 1:
        return False
    for n in (9, 10):
        check = sum(d[i] * (n + 1 - i) for i in range(n)) * 10 % 11 % 10
        if check != d[n]:
            return False
    return True


def _cn_id_ok(s: str) -> bool:
    s = s.strip().upper()
    if not re.match(r"^\d{17}[\dX]$", s):
        return False
    weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    return "10X98765432"[sum(int(c) * w for c, w in zip(s[:17], weights)) % 11] == s[17]


def _iban_ok(s: str) -> bool:
    s = s.replace(" ", "").upper()
    if not _IBAN.match(s):
        return False
    rearranged = s[4:] + s[:4]
    num = "".join(str(int(ch, 36)) for ch in rearranged)
    return int(num) % 97 == 1


def _ratio(values: list, pred) -> float:
    return sum(1 for v in values if pred(v)) / len(values) if values else 0.0


def content_score(clf: dict, values: list[Any]) -> tuple[float, float, list[Any]]:
    """Returns (content_score 0..1, raw match ratio, a few matching values)."""
    method = clf["content_method"]
    vals = [v for v in values if v is not None and str(v).strip() != ""]
    if not vals:
        return 0.0, 0.0, []
    matched: list[Any] = []

    def counted(pred):
        nonlocal matched
        out = [v for v in vals if pred(v)]
        matched = out
        return len(out) / len(vals)

    strs = [str(v).strip() for v in vals]
    if method == "REGEX":
        pat = re.compile(clf["content_pattern"]) if clf.get("content_pattern") else _EMAIL
        ratio = counted(lambda v: bool(pat.match(str(v).strip())))
    elif method == "PHONE":
        ratio = counted(lambda v: bool(_PHONE_INTL.match(str(v).strip()) or _PHONE_LOCAL.match(str(v).strip())))
    elif method == "DICT_FIRST":
        ratio = counted(lambda v: str(v).strip().lower() in FIRST_NAMES)
    elif method == "DICT_LAST":
        ratio = counted(lambda v: str(v).strip().lower() in LAST_NAMES)
    elif method == "FULL_NAME":
        def is_full(v):
            t = str(v).strip().split()
            return len(t) >= 2 and t[0].lower() in FIRST_NAMES and t[-1].lower() in LAST_NAMES
        ratio = counted(is_full)
    elif method == "ENUM":
        allowed = {x.strip().upper() for x in (clf["content_pattern"] or "").split(",")}
        ratio = counted(lambda v: str(v).strip().upper() in allowed)
        if len(set(strs)) > 8:  # a real enum has few distinct values
            ratio *= 0.3
    elif method == "LUHN":
        ratio = counted(lambda v: _luhn(str(v)))
    elif method == "IBAN":
        ratio = counted(lambda v: _iban_ok(str(v)))
    elif method == "REGEX_LUHN":
        pat = re.compile(clf["content_pattern"])
        ratio = counted(lambda v: bool(pat.match(str(v).strip())) and _luhn_valid(str(v)))
    elif method == "CPF":
        ratio = counted(lambda v: _cpf_ok(str(v)))
    elif method == "CN_ID":
        ratio = counted(lambda v: _cn_id_ok(str(v)))
    elif method == "KEYWORD":
        terms = [t.strip().lower() for t in (clf["content_pattern"] or "").split(",") if t.strip()]

        def has_term(v):
            return any(tok.startswith(t) for tok in re.split(r"[^a-z0-9]+", str(v).lower()) if tok for t in terms)
        ratio = counted(has_term)
    elif method == "NUMERIC":
        ratio = counted(lambda v: isinstance(v, (int, float)) and v > 0)
    elif method == "DOB":
        today = dt.datetime.now()
        years = [v.year for v in vals if isinstance(v, (dt.date, dt.datetime))]
        if not years:
            return 0.0, 0.0, []
        plausible = sum(1 for v in vals if isinstance(v, (dt.date, dt.datetime))
                        and dt.datetime(1900, 1, 1) <= dt.datetime(v.year, v.month, v.day) <= today)
        plaus_ratio = plausible / len(vals)
        spread = min(1.0, (statistics.pstdev(years) if len(years) > 1 else 0.0) / 12.0)
        matched = vals[:5] if plaus_ratio * spread >= 0.5 else []
        return plaus_ratio * spread, plaus_ratio, matched
    else:                                     # NONE: name evidence only
        return 0.0, 0.0, []
    mm = clf.get("min_match_ratio")
    if mm:                                     # sparse evidence: a small share of matching rows is already strong
        return min(1.0, ratio / float(mm)), ratio, matched
    score = ratio if ratio >= 0.5 else ratio * 0.5
    return score, ratio, matched


def name_hit(clf: dict, column_name: str) -> bool:
    pat = clf.get("name_pattern")
    return bool(pat and re.search(pat, column_name, re.I))


def applies(clf: dict, dtype: str) -> bool:
    a = clf["applies_to"]
    if a == "STRING":
        return dtype in ("VARCHAR2", "CHAR", "NVARCHAR2", "NCHAR")
    if a == "DATE":
        return dtype in ("DATE", "TIMESTAMP")
    if a == "NUMBER":
        return dtype == "NUMBER"
    return True


def score_column(clf: dict, column_name: str, dtype: str, values: list[Any] | None, metadata_only: bool) -> dict | None:
    """Score one classifier against one column. None when the classifier does not apply."""
    if not applies(clf, dtype):
        return None
    hit = name_hit(clf, column_name)
    if metadata_only:
        conf = 0.6 * hit                        # name evidence alone is capped: it always needs review
        return {"confidence": round(conf, 3), "name_hit": hit, "match_ratio": None, "rows_sampled": 0, "samples": []}
    score, ratio, samples = content_score(clf, values or [])
    conf = clf["name_weight"] * (1.0 if hit else 0.0) + clf["content_weight"] * score
    return {"confidence": round(min(conf, 1.0), 3), "name_hit": hit, "match_ratio": round(ratio, 4),
            "rows_sampled": len(values or []), "samples": samples[:3]}


def score_from_ratio(clf: dict, column_name: str, dtype: str, ratio: float, rows_sampled: int,
                     samples: list[Any], metadata_only: bool) -> dict | None:
    """Same confidence combination as score_column(), but `ratio` was computed by a predicate pushed
    down to the source's own compute (rg/scanner.py's PUSHDOWN_PREDICATES, rg/engines/databricks.py /
    rg/engines/snowflake.py's governance UDFs) instead of pulling raw values back and running
    content_score() locally - so rows_sampled here is the table's real row count, not a local sample size."""
    if not applies(clf, dtype):
        return None
    hit = name_hit(clf, column_name)
    if metadata_only:
        conf = 0.6 * hit
        return {"confidence": round(conf, 3), "name_hit": hit, "match_ratio": None, "rows_sampled": 0, "samples": []}
    score = ratio if ratio >= 0.5 else ratio * 0.5
    conf = clf["name_weight"] * (1.0 if hit else 0.0) + clf["content_weight"] * score
    return {"confidence": round(min(conf, 1.0), 3), "name_hit": hit, "match_ratio": round(ratio, 4),
            "rows_sampled": rows_sampled, "samples": samples[:3]}


def status_for(conf: float) -> str | None:
    if conf >= AUTO_THRESHOLD:
        return "AUTO"
    if conf >= REVIEW_THRESHOLD:
        return "NEEDS_REVIEW"
    if conf >= LOW_THRESHOLD:
        return "LOW"
    return None
