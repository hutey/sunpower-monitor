"""
Unit tests for sunpower_monitor.py

Run with:  pytest test_sunpower_monitor.py -v
"""

import json
import os
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Set env vars before the module is imported so it doesn't error on missing password
os.environ.setdefault("PVS_HOST", "192.168.1.99")
os.environ.setdefault("PVS_PASSWORD", "TEST1")

import sunpower_monitor as spm


# ── Helpers ───────────────────────────────────────────────────────────────────

def _inverter_flat(idx="0", sn="ZT12345678", kw="2.0", kwh="500.0"):
    b = f"/sys/devices/inverter/{idx}"
    return {
        f"{b}/sn": sn,
        f"{b}/pMppt1Kw": kw,
        f"{b}/ltea3phsumKwh": kwh,
        f"{b}/vln3phavgV": "240.0",
        f"{b}/vMppt1V": "30.0",
        f"{b}/iMppt1A": "5.0",
        f"{b}/freqHz": "60.0",
        f"{b}/prodMdlNm": "SPN-370",
    }


def _meter_flat(idx="0", suffix="p", sn="M001", i1="5.0", i2="5.0",
                pos_kwh="100.0", neg_kwh="50.0"):
    b = f"/sys/devices/meter/{idx}"
    return {
        f"{b}/prodMdlNm": f"PVS5-{suffix}",
        f"{b}/sn": sn,
        f"{b}/p3phsumKw": "2.0",
        f"{b}/p1Kw": "1.0",
        f"{b}/p2Kw": "1.0",
        f"{b}/i1A": i1,
        f"{b}/i2A": i2,
        f"{b}/v1nV": "120.0",
        f"{b}/v2nV": "120.0",
        f"{b}/v12V": "240.0",
        f"{b}/freqHz": "60.0",
        f"{b}/totPfRto": "0.98",
        f"{b}/ctSclFctr": "1.0",
        f"{b}/s3phsumKva": "2.1",
        f"{b}/q3phsumKvar": "0.2",
        f"{b}/posLtea3phsumKwh": pos_kwh,
        f"{b}/negLtea3phsumKwh": neg_kwh,
        f"{b}/netLtea3phsumKwh": "50.0",
    }


SYSINFO = {
    "/sys/info/sw_rev": "1.2.3",
    "/sys/info/hwrev": "A1",
    "/sys/info/fwrev": "2025.09",
    "/sys/info/lmac": "AA:BB:CC:DD:EE:FF",
}


def _varserver_side_effect(inverters, meters, livedata, sysinfo=None):
    si = sysinfo or SYSINFO
    def side_effect(qs):
        if qs.startswith("match=inverter"):   return inverters
        if qs.startswith("match=meter"):      return meters
        if qs.startswith("match=/sys/livedata"): return livedata
        if qs.startswith("match=/sys/info"):  return si
        return {}
    return side_effect


# ── _redact_str ───────────────────────────────────────────────────────────────

class TestRedactStr:

    def test_redacts_all_but_last_4(self):
        assert spm._redact_str("ABCDE12345") == "••••2345"

    def test_string_exactly_keep_length_returns_bullets_only(self):
        assert spm._redact_str("ABCD", keep=4) == "••••"

    def test_string_shorter_than_keep_returns_bullets_only(self):
        assert spm._redact_str("AB", keep=4) == "••••"

    def test_empty_string_unchanged(self):
        assert spm._redact_str("") == ""

    def test_dash_sentinel_unchanged(self):
        assert spm._redact_str("—") == "—"

    def test_none_unchanged(self):
        assert spm._redact_str(None) is None

    def test_non_string_coerced(self):
        assert spm._redact_str(12345678) == "••••5678"

    def test_custom_keep_length(self):
        assert spm._redact_str("1234567890", keep=6) == "••••567890"


# ── _group_by_device ──────────────────────────────────────────────────────────

class TestGroupByDevice:

    def test_single_device_single_field(self):
        flat = {"/sys/devices/inverter/0/sn": "ABC123"}
        assert spm._group_by_device(flat) == {"0": {"sn": "ABC123"}}

    def test_single_device_multiple_fields(self):
        flat = {
            "/sys/devices/inverter/0/sn": "ABC123",
            "/sys/devices/inverter/0/pMppt1Kw": "1.5",
        }
        assert spm._group_by_device(flat) == {"0": {"sn": "ABC123", "pMppt1Kw": "1.5"}}

    def test_multiple_devices_grouped_by_index(self):
        flat = {
            "/sys/devices/inverter/0/sn": "AAA",
            "/sys/devices/inverter/1/sn": "BBB",
        }
        result = spm._group_by_device(flat)
        assert result == {"0": {"sn": "AAA"}, "1": {"sn": "BBB"}}

    def test_short_path_skipped(self):
        assert spm._group_by_device({"/sys/info": "val"}) == {}

    def test_empty_input(self):
        assert spm._group_by_device({}) == {}


# ── _load_config ──────────────────────────────────────────────────────────────

class TestLoadConfig:

    def test_valid_config_file(self, tmp_path):
        cfg = {"pvs_host": "10.0.0.1", "pvs_password": "ABCDE"}
        (tmp_path / "config.json").write_text(json.dumps(cfg))
        with patch.object(spm, "__file__", str(tmp_path / "sunpower_monitor.py")):
            assert spm._load_config() == cfg

    def test_missing_file_returns_empty(self, tmp_path):
        with patch.object(spm, "__file__", str(tmp_path / "sunpower_monitor.py")):
            assert spm._load_config() == {}

    def test_invalid_json_returns_empty(self, tmp_path):
        (tmp_path / "config.json").write_text("not { valid json")
        with patch.object(spm, "__file__", str(tmp_path / "sunpower_monitor.py")):
            assert spm._load_config() == {}


# ── redact_for_public ─────────────────────────────────────────────────────────

class TestRedactForPublic:

    def _data(self):
        return {
            "supervisor": {"mac": "AA:BB:CC:DD:EE:FF", "sw_rev": "1.0"},
            "panels": [
                {"serial": "ZT1234567890", "serial_short": "567890"},
                {"serial": "ZT0987654321", "serial_short": "654321"},
            ],
            "diagnostics": {
                "production_meter":  {"serial": "M111111"},
                "consumption_meter": {"serial": "M222222"},
            },
            "pvs_host": "https://192.168.1.99",
            "access": "trusted",
        }

    def test_mac_redacted(self):
        result = spm.redact_for_public(self._data())
        assert result["supervisor"]["mac"].startswith("••••")

    def test_panel_serials_redacted(self):
        result = spm.redact_for_public(self._data())
        assert all(p["serial"].startswith("••••") for p in result["panels"])

    def test_meter_serials_redacted(self):
        result = spm.redact_for_public(self._data())
        assert result["diagnostics"]["production_meter"]["serial"].startswith("••••")
        assert result["diagnostics"]["consumption_meter"]["serial"].startswith("••••")

    def test_pvs_host_hidden(self):
        assert spm.redact_for_public(self._data())["pvs_host"] == "••••"

    def test_access_set_to_public(self):
        assert spm.redact_for_public(self._data())["access"] == "public"

    def test_original_data_not_mutated(self):
        data = self._data()
        spm.redact_for_public(data)
        assert data["pvs_host"] == "https://192.168.1.99"
        assert data["panels"][0]["serial"] == "ZT1234567890"

    def test_none_meter_does_not_raise(self):
        data = self._data()
        data["diagnostics"]["production_meter"] = None
        result = spm.redact_for_public(data)
        assert result["diagnostics"]["production_meter"] is None


# ── record_reading ────────────────────────────────────────────────────────────

class TestRecordReading:

    @pytest.fixture(autouse=True)
    def reset_history(self, tmp_path, monkeypatch):
        monkeypatch.setattr(spm, "HISTORY_FILE", tmp_path / "history.json")
        monkeypatch.setattr(spm, "_history_cache", None)

    def test_first_reading_sets_baseline_delta_is_zero(self):
        assert spm.record_reading("SN001", 100.0) == 0.0

    def test_subsequent_reading_returns_delta(self):
        spm.record_reading("SN001", 100.0)
        assert spm.record_reading("SN001", 102.5) == pytest.approx(2.5)

    def test_negative_delta_clamped_to_zero(self):
        spm.record_reading("SN001", 100.0)
        assert spm.record_reading("SN001", 99.0) == 0.0

    def test_multiple_serials_tracked_independently(self):
        spm.record_reading("SN001", 100.0)
        spm.record_reading("SN002", 200.0)
        assert spm.record_reading("SN001", 101.0) == pytest.approx(1.0)
        assert spm.record_reading("SN002", 205.0) == pytest.approx(5.0)

    def test_history_written_to_disk(self, tmp_path):
        spm.record_reading("SN001", 50.0)
        assert spm.HISTORY_FILE.exists()
        data = json.loads(spm.HISTORY_FILE.read_text())
        assert "baselines" in data and "last_seen" in data

    def test_delta_rounded_to_3_decimals(self):
        spm.record_reading("SN001", 0.0)
        result = spm.record_reading("SN001", 1.0005)
        assert result == round(1.0005, 3)

    def test_grid_pseudo_serials_work(self):
        spm.record_reading("__grid_import__", 10.0)
        assert spm.record_reading("__grid_import__", 11.5) == pytest.approx(1.5)


# ── is_tailscale_direct ───────────────────────────────────────────────────────

class TestIsTailscaleDirect:

    def test_loopback_is_trusted(self):
        with spm.app.test_request_context("/", environ_base={"REMOTE_ADDR": "127.0.0.1"}):
            assert spm.is_tailscale_direct() is True

    def test_tailscale_cgnat_low_end_trusted(self):
        with spm.app.test_request_context("/", environ_base={"REMOTE_ADDR": "100.64.0.1"}):
            assert spm.is_tailscale_direct() is True

    def test_tailscale_cgnat_high_end_trusted(self):
        with spm.app.test_request_context("/", environ_base={"REMOTE_ADDR": "100.127.255.255"}):
            assert spm.is_tailscale_direct() is True

    def test_public_ip_not_trusted(self):
        with spm.app.test_request_context("/", environ_base={"REMOTE_ADDR": "8.8.8.8"}):
            assert spm.is_tailscale_direct() is False

    def test_x_forwarded_for_means_funnel_even_on_tailscale_ip(self):
        with spm.app.test_request_context(
            "/",
            environ_base={"REMOTE_ADDR": "100.64.1.1"},
            environ_overrides={"HTTP_X_FORWARDED_FOR": "1.2.3.4"},
        ):
            assert spm.is_tailscale_direct() is False

    def test_invalid_ip_returns_false(self):
        with spm.app.test_request_context("/", environ_base={"REMOTE_ADDR": "not-an-ip"}):
            assert spm.is_tailscale_direct() is False


# ── rate_limit ────────────────────────────────────────────────────────────────

class TestRateLimit:

    @pytest.fixture(autouse=True)
    def clear_rl_store(self):
        spm._rl_store.clear()
        yield
        spm._rl_store.clear()

    def test_first_request_allowed(self):
        with spm.app.test_request_context("/api/data", environ_base={"REMOTE_ADDR": "1.2.3.4"}):
            assert spm.rate_limit() is None

    def test_requests_under_limit_allowed(self):
        ip = "1.2.3.5"
        now = time.time()
        spm._rl_store[ip] = [now] * (spm.RL_LIMIT - 1)
        with spm.app.test_request_context("/api/data", environ_base={"REMOTE_ADDR": ip}):
            assert spm.rate_limit() is None

    def test_exceeding_limit_returns_429(self):
        ip = "1.2.3.6"
        now = time.time()
        spm._rl_store[ip] = [now] * spm.RL_LIMIT
        with spm.app.test_request_context("/api/data", environ_base={"REMOTE_ADDR": ip}):
            result = spm.rate_limit()
        assert result is not None
        _, status = result
        assert status == 429

    def test_non_api_route_bypasses_rate_limit(self):
        ip = "1.2.3.7"
        spm._rl_store[ip] = [time.time()] * (spm.RL_LIMIT + 100)
        with spm.app.test_request_context("/", environ_base={"REMOTE_ADDR": ip}):
            assert spm.rate_limit() is None

    def test_expired_hits_outside_window_are_pruned(self):
        ip = "1.2.3.8"
        old = time.time() - spm.RL_WINDOW - 1
        spm._rl_store[ip] = [old] * spm.RL_LIMIT   # all expired
        with spm.app.test_request_context("/api/data", environ_base={"REMOTE_ADDR": ip}):
            assert spm.rate_limit() is None

    def test_x_forwarded_for_used_as_ip_key(self):
        real_ip = "10.0.0.1"
        forwarded_ip = "203.0.113.5"
        now = time.time()
        # Pre-fill limit for the forwarded IP
        spm._rl_store[forwarded_ip] = [now] * spm.RL_LIMIT
        with spm.app.test_request_context(
            "/api/data",
            environ_base={"REMOTE_ADDR": real_ip},
            environ_overrides={"HTTP_X_FORWARDED_FOR": forwarded_ip},
        ):
            result = spm.rate_limit()
        _, status = result
        assert status == 429


# ── fetch_all_data ────────────────────────────────────────────────────────────

class TestFetchAllData:
    """Tests for fetch_all_data with varserver_get mocked out."""

    @pytest.fixture(autouse=True)
    def reset_history(self, tmp_path, monkeypatch):
        monkeypatch.setattr(spm, "HISTORY_FILE", tmp_path / "history.json")
        monkeypatch.setattr(spm, "_history_cache", None)

    def _fetch(self, inverters, livedata, meters=None, sysinfo=None):
        if meters is None:
            meters = {**_meter_flat("0", "p"), **_meter_flat("1", "c")}
        with patch("sunpower_monitor.varserver_get",
                   side_effect=_varserver_side_effect(inverters, meters, livedata, sysinfo)):
            return spm.fetch_all_data()

    # ── Panel state ──────────────────────────────────────────────────────────

    def test_panel_state_working_when_producing(self):
        data = self._fetch(
            _inverter_flat(kw="1.5"),
            {"/sys/livedata/pv_p": "1.5", "/sys/livedata/net_p": "0.5",
             "/sys/livedata/site_load_p": "2.0", "/sys/livedata/pv_en": "500.0"},
        )
        assert data["panels"][0]["state"] == "working"

    def test_panel_state_idle_when_zero_output(self):
        data = self._fetch(
            _inverter_flat(kw="0.0"),
            {"/sys/livedata/pv_p": "0.0", "/sys/livedata/net_p": "0.5",
             "/sys/livedata/site_load_p": "0.5", "/sys/livedata/pv_en": "500.0"},
        )
        assert data["panels"][0]["state"] == "idle"

    def test_panels_sorted_by_serial_short(self):
        inv = {
            **_inverter_flat(idx="0", sn="ZT000ZZZ"),
            **_inverter_flat(idx="1", sn="ZT000AAA"),
        }
        data = self._fetch(inv, {})
        serials = [p["serial_short"] for p in data["panels"]]
        assert serials == sorted(serials)

    # ── Grid direction ───────────────────────────────────────────────────────

    def test_grid_direction_export(self):
        data = self._fetch(
            _inverter_flat(kw="8.0"),
            {"/sys/livedata/pv_p": "8.0", "/sys/livedata/net_p": "-3.0",
             "/sys/livedata/site_load_p": "5.0", "/sys/livedata/pv_en": "1000.0"},
        )
        assert data["summary"]["grid_direction"] == "export"
        assert data["summary"]["grid_kw"] == pytest.approx(-3.0)

    def test_grid_direction_import(self):
        data = self._fetch(
            _inverter_flat(kw="1.0"),
            {"/sys/livedata/pv_p": "1.0", "/sys/livedata/net_p": "2.5",
             "/sys/livedata/site_load_p": "3.5", "/sys/livedata/pv_en": "1000.0"},
        )
        assert data["summary"]["grid_direction"] == "import"

    def test_grid_direction_idle_near_zero(self):
        data = self._fetch(
            _inverter_flat(kw="2.0"),
            {"/sys/livedata/pv_p": "2.0", "/sys/livedata/net_p": "0.02",
             "/sys/livedata/site_load_p": "2.02", "/sys/livedata/pv_en": "1000.0"},
        )
        assert data["summary"]["grid_direction"] == "idle"

    def test_grid_direction_unknown_when_net_missing(self):
        data = self._fetch(
            _inverter_flat(kw="2.0"),
            {"/sys/livedata/pv_p": "2.0", "/sys/livedata/pv_en": "1000.0"},
        )
        assert data["summary"]["grid_direction"] == "unknown"

    # ── CT clamp correction ──────────────────────────────────────────────────

    def test_ct_correction_applied_for_negative_home_load(self):
        data = self._fetch(
            _inverter_flat(kw="8.0"),
            {"/sys/livedata/pv_p": "8.0", "/sys/livedata/net_p": "-5.75",
             "/sys/livedata/site_load_p": "-5.75",   # flipped CT
             "/sys/livedata/pv_en": "1000.0"},
        )
        assert data["summary"]["ct_corrected"] is True
        assert data["summary"]["home_kw"] == pytest.approx(2.25)
        assert data["summary"]["grid_direction"] == "export"

    def test_ct_correction_not_triggered_below_threshold(self):
        # -0.05 is above the -0.1 threshold — should not trigger
        data = self._fetch(
            _inverter_flat(kw="2.0"),
            {"/sys/livedata/pv_p": "2.0", "/sys/livedata/net_p": "0.0",
             "/sys/livedata/site_load_p": "-0.05",
             "/sys/livedata/pv_en": "1000.0"},
        )
        assert data["summary"]["ct_corrected"] is False

    def test_ct_correction_disabled_by_config(self):
        # With CT_CORRECTION=False, a negative home_kw is passed through as-is
        with patch.object(spm, "CT_CORRECTION", False):
            data = self._fetch(
                _inverter_flat(kw="8.0"),
                {"/sys/livedata/pv_p": "8.0", "/sys/livedata/net_p": "-5.75",
                 "/sys/livedata/site_load_p": "-5.75",
                 "/sys/livedata/pv_en": "1000.0"},
            )
        assert data["summary"]["ct_corrected"] is False
        assert data["summary"]["home_kw"] == pytest.approx(-5.75)

    def test_ct_correction_clamps_home_kw_to_zero(self):
        # PV 1 kW, home_kw = -5 → corrected = max(0, 1 + (-5)) = 0
        data = self._fetch(
            _inverter_flat(kw="1.0"),
            {"/sys/livedata/pv_p": "1.0", "/sys/livedata/net_p": "-5.0",
             "/sys/livedata/site_load_p": "-5.0",
             "/sys/livedata/pv_en": "1000.0"},
        )
        assert data["summary"]["home_kw"] == 0.0

    # ── Diagnostic warnings ──────────────────────────────────────────────────

    def test_warning_low_load_when_pv_high_home_low(self):
        meters = {**_meter_flat("0", "p"), **_meter_flat("1", "c", i1="1.0", i2="1.0")}
        data = self._fetch(
            _inverter_flat(kw="3.0"),
            {"/sys/livedata/pv_p": "3.0", "/sys/livedata/net_p": "-2.9",
             "/sys/livedata/site_load_p": "0.1",
             "/sys/livedata/pv_en": "1000.0"},
            meters=meters,
        )
        assert any(w["kind"] == "low_load" for w in data["diagnostics"]["warnings"])

    def test_warning_ct_coverage_when_current_suspiciously_low(self):
        meters = {**_meter_flat("0", "p"), **_meter_flat("1", "c", i1="1.0", i2="0.5")}
        data = self._fetch(
            _inverter_flat(kw="4.0"),
            {"/sys/livedata/pv_p": "4.0", "/sys/livedata/net_p": "-3.5",
             "/sys/livedata/site_load_p": "0.5",   # above 0.3 so low_load doesn't fire
             "/sys/livedata/pv_en": "1000.0"},
            meters=meters,
        )
        assert any(w["kind"] == "ct_coverage" for w in data["diagnostics"]["warnings"])

    def test_warning_ct_corrected_added_when_correction_applied(self):
        data = self._fetch(
            _inverter_flat(kw="8.0"),
            {"/sys/livedata/pv_p": "8.0", "/sys/livedata/net_p": "-5.0",
             "/sys/livedata/site_load_p": "-5.0",
             "/sys/livedata/pv_en": "1000.0"},
        )
        assert any(w["kind"] == "ct_corrected" for w in data["diagnostics"]["warnings"])

    def test_no_warnings_in_normal_operation(self):
        meters = {**_meter_flat("0", "p"), **_meter_flat("1", "c", i1="10.0", i2="12.0")}
        data = self._fetch(
            _inverter_flat(kw="4.0"),
            {"/sys/livedata/pv_p": "4.0", "/sys/livedata/net_p": "-1.5",
             "/sys/livedata/site_load_p": "2.5",
             "/sys/livedata/pv_en": "1000.0"},
            meters=meters,
        )
        assert data["diagnostics"]["warnings"] == []

    # ── Meter failures ───────────────────────────────────────────────────────

    def test_meter_failure_degrades_gracefully(self):
        def side_effect(qs):
            if "meter" in qs:   raise ConnectionError("meter offline")
            if "inverter" in qs: return _inverter_flat(kw="2.0")
            if "livedata" in qs: return {"/sys/livedata/pv_p": "2.0", "/sys/livedata/pv_en": "500.0"}
            return SYSINFO

        with patch("sunpower_monitor.varserver_get", side_effect=side_effect):
            data = spm.fetch_all_data()

        assert len(data["panels"]) == 1
        assert data["summary"]["total_kw"] == pytest.approx(2.0)

    def test_livedata_failure_falls_back_to_inverter_totals(self):
        def side_effect(qs):
            if "livedata" in qs: raise ConnectionError("livedata offline")
            if "inverter" in qs: return _inverter_flat(kw="3.0")
            if "meter" in qs:    return {**_meter_flat("0", "p"), **_meter_flat("1", "c")}
            return SYSINFO

        with patch("sunpower_monitor.varserver_get", side_effect=side_effect):
            data = spm.fetch_all_data()

        # Falls back to summing inverter kW directly
        assert data["summary"]["total_kw"] == pytest.approx(3.0)

    # ── Aggregation ──────────────────────────────────────────────────────────

    def test_panels_online_count(self):
        inv = {
            **_inverter_flat(idx="0", kw="2.0"),
            **_inverter_flat(idx="1", kw="0.0"),
        }
        data = self._fetch(inv, {})
        assert data["summary"]["panels_online"] == 1
        assert data["summary"]["panels_offline"] == 1

    def test_supervisor_fields_populated(self):
        data = self._fetch(
            _inverter_flat(),
            {},
            sysinfo=SYSINFO,
        )
        sup = data["supervisor"]
        assert sup["sw_rev"] == "1.2.3"
        assert sup["mac"] == "AA:BB:CC:DD:EE:FF"


# ── write_var ─────────────────────────────────────────────────────────────────

class TestWriteVar:

    def test_success_200(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"description": "OK"}
        with patch.object(spm._session, "post", return_value=mock_resp):
            with patch.object(spm, "_authenticated", True):
                ok, status, msg = spm.write_var("/sys/some/var", "1")
        assert ok is True
        assert status == 200
        assert msg == "OK"

    def test_failure_403(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.json.return_value = {"description": "Forbidden"}
        with patch.object(spm._session, "post", return_value=mock_resp):
            with patch.object(spm, "_authenticated", True):
                ok, status, _ = spm.write_var("/sys/some/var", "1")
        assert ok is False
        assert status == 403

    def test_non_json_response_handled(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.json.side_effect = ValueError("not json")
        mock_resp.text = "Internal server error"
        with patch.object(spm._session, "post", return_value=mock_resp):
            with patch.object(spm, "_authenticated", True):
                ok, status, msg = spm.write_var("/sys/some/var", "1")
        assert ok is False
        assert "Internal server error" in msg
