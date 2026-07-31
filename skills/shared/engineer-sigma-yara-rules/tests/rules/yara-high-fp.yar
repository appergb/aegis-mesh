rule Aegis_Mesh_Synthetic_High_FP
{
    meta:
        source = "urn:aegis-mesh:synthetic:yara-high-fp"
        sample_hash = "sha256:cf6afee8207894bc90e41311a50fe4a9d4b7251d70b83a16e14e6d5184ad57b6"
        author = "Aegis Mesh Detection Engineering"
        date = "2026-07-30"
        version = "1.0.0"
        purpose = "Synthetic high false-positive package validation"
        false_positive_notes = "Intentionally matches the common synthetic format marker"
        max_fixture_bytes = 1048576
    strings:
        $common = "AEGIS_MESH_SYNTHETIC_FORMAT" ascii fullword
    condition:
        uint16(0) == 0x5a4d and filesize <= 1048576 and $common
}
