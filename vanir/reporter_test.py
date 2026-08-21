# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Tests for the Reporter verifying missing patch string parsing and formats."""

import dataclasses
from unittest import mock

from absl.testing import parameterized
from vanir import reporter
from vanir import vulnerability_manager

from absl.testing import absltest


_TEST_SIGN_ID = 'asb-a-test-sign-1234'
_TEST_TARGET_FILE = 'foo/bar/target_file.c'
_TEST_TARGET_FUNC = 'target_func1'
_TEST_SOURCE = 'https://android.googlesource.com/some/test/source'
_TEST_UNPATCHED_FILE = 'foo/bar/unpatched_file.c'
_TEST_UNPATCHED_FUNC = 'unpatched_func1'
_TEST_IS_NON_TARGET_MATCH = True


class ReporterTest(parameterized.TestCase):

  def setUp(self):
    super().setUp()
    self._test_report = reporter.Report(
        _TEST_SIGN_ID,
        _TEST_TARGET_FILE,
        _TEST_TARGET_FUNC,
        _TEST_SOURCE,
        _TEST_UNPATCHED_FILE,
        _TEST_UNPATCHED_FUNC,
        _TEST_IS_NON_TARGET_MATCH,
    )

  def test_get_simple_report(self):
    expected_simple_report = (
        'foo/bar/unpatched_file.c::unpatched_func1() (matched from'
        ' foo/bar/target_file.c::target_func1())'
    )
    self.assertEqual(
        self._test_report.get_simple_report(), expected_simple_report
    )

  def test_from_simple_report(self):
    # Verify that formatting a Report to a simple string and parsing it back
    # yields the identical Report object.
    # include_patch_source=True, use_html_link_for_patch_source=False
    str_format = self._test_report.get_simple_report(
        include_patch_source=True, use_html_link_for_patch_source=False
    )
    parsed = reporter.Report.from_simple_report(str_format)
    self.assertEqual(parsed, self._test_report)

    # include_patch_source=True, use_html_link_for_patch_source=True
    str_format_html = self._test_report.get_simple_report(
        include_patch_source=True, use_html_link_for_patch_source=True
    )
    parsed_html = reporter.Report.from_simple_report(str_format_html)
    self.assertEqual(parsed_html, self._test_report)

  def test_from_simple_report_target_match(self):
    report_target = dataclasses.replace(
        self._test_report,
        is_non_target_match=False,
        signature_target_file='',
        signature_target_function='',
    )
    str_format = report_target.get_simple_report(include_patch_source=True)
    parsed = reporter.Report.from_simple_report(str_format)
    self.assertEqual(parsed, report_target)

  def test_generate_report_book(self):
    reports = []
    for i in range(10):
      new_sign_id = _TEST_SIGN_ID + str(i)
      new_source = _TEST_SOURCE + str(i)
      report = dataclasses.replace(
          self._test_report,
          signature_id=new_sign_id,
          signature_source=new_source,
      )
      reports.append(report)
    mock_vul_manager = mock.create_autospec(
        vulnerability_manager.VulnerabilityManager, instance=True
    )
    mock_vul_manager.sign_id_to_osv_id.side_effect = (
        lambda sign_id: f'osv-id-{sign_id[-1]}'
    )
    mock_vul_manager.osv_id_to_cve_ids.side_effect = (
        lambda osv_id: [osv_id.replace('osv', 'cve')]
    )
    test_report_book = reporter.ReportBook(reports, mock_vul_manager)
    expected_unpatched_vuls = [f'osv-id-{i}' for i in range(10)]
    self.assertEqual(
        test_report_book.unpatched_vulnerabilities, expected_unpatched_vuls
    )
    expected_unpatched_cves = [f'cve-id-{i}' for i in range(10)]
    self.assertEqual(test_report_book.unpatched_cves, expected_unpatched_cves)
    embedded_reports = []
    for osv_id in test_report_book.unpatched_vulnerabilities:
      rgroup = test_report_book.get_report_group(osv_id)
      embedded_reports += rgroup.reports
    self.assertCountEqual(embedded_reports, reports)

  @parameterized.named_parameters(
      dict(
          testcase_name='basic',
          report=reporter.Report(
              signature_id='',
              signature_target_file='',
              signature_target_function='',
              signature_source='',
              unpatched_file='target.c',
              unpatched_function_name='vuln',
              is_non_target_match=False,
          ),
          kwargs={},
      ),
      dict(
          testcase_name='with_patch',
          report=reporter.Report(
              signature_id='test-sig',
              signature_target_file='',
              signature_target_function='',
              signature_source='http://patch',
              unpatched_file='target.c',
              unpatched_function_name='vuln',
              is_non_target_match=False,
          ),
          kwargs=dict(include_patch_source=True),
      ),
      dict(
          testcase_name='with_html_patch',
          report=reporter.Report(
              signature_id='test-sig',
              signature_target_file='',
              signature_target_function='',
              signature_source='http://patch',
              unpatched_file='target.c',
              unpatched_function_name='vuln',
              is_non_target_match=False,
          ),
          kwargs=dict(
              include_patch_source=True, use_html_link_for_patch_source=True
          ),
      ),
      dict(
          testcase_name='non_target_match_with_patch',
          report=reporter.Report(
              signature_id='test-sig',
              signature_target_file='target.c',
              signature_target_function='vuln',
              signature_source='http://patch',
              unpatched_file='other.c',
              unpatched_function_name='vuln',
              is_non_target_match=True,
          ),
          kwargs=dict(include_patch_source=True),
      ),
  )
  def test_simple_report_conversion(self, report, kwargs):
    report_str = report.get_simple_report(**kwargs)
    parsed_report = reporter.Report.from_simple_report(report_str)
    self.assertEqual(parsed_report, report)

  @parameterized.named_parameters(
      dict(
          testcase_name='empty_string',
          report_str='',
      ),
      dict(
          testcase_name='whitespace_only',
          report_str='   ',
      ),
      dict(
          testcase_name='missing_file_only_patch',
          report_str='(patch:http://patch, signature:test-sig)',
      ),
      dict(
          testcase_name='missing_file_only_function',
          report_str='::vuln()',
      ),
  )
  def test_from_simple_report_invalid(self, report_str):
    self.assertIsNone(reporter.Report.from_simple_report(report_str))


if __name__ == '__main__':
  absltest.main()
