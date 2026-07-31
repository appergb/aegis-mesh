rule Aegis_Mesh_Synthetic_Marker
{
    meta:
        source = "urn:aegis-mesh:synthetic:yara-marker"
        sample_hash = "sha256:79b42a3dd04f61f02c8d0c8db331ebc42c7b731041b69cd08f9a342fa2c0d8aa"
        author = "Aegis Mesh Detection Engineering"
        date = "2026-07-30"
        version = "1.0.0"
        purpose = "Synthetic defensive package validation"
        false_positive_notes = "Synthetic test content intentionally reusing the marker"
        max_fixture_bytes = 1048576
    strings:
        $format = "AEGIS_MESH_SYNTHETIC_FORMAT" ascii fullword
        $marker = "AEGIS_MESH_SYNTHETIC_SUSPICIOUS_MARKER" ascii fullword
    condition:
        uint16(0) == 0x5a4d and filesize <= 1048576 and all of them
}
