# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Reporter module for managing Vanir report data structures."""

import collections
import dataclasses
import functools
import itertools
import re
from typing import Optional, Sequence, Union
from typing_extensions import Self

from vanir import vulnerability_manager
from vanir.scanners import scanner_base

# Report String Formatting Templates
_FUNC_SUFFIX_FORMAT = '::{func_name}()'
_PATCH_SOURCE_FORMAT = '  (patch:{patch_source}, signature:{signature_id})'
_HTML_PATCH_SOURCE_FORMAT = (
    '  (<a href="{patch_source}">patch</a>, {signature_id})'
)
_MATCHED_FROM_FORMAT = ' (matched from {target_code})'

_SIMPLE_REPORT_REGEX = re.compile(
    r'^\s*(?P<unpatched_file>[^\s(:]+)'
    r'(?:::(?P<unpatched_function>[^()]+)\(\))?'
    r'(?:\s+\(\s*(?:patch:\s*(?P<url>[^\s,]+)|'
    r'<a href="(?P<html_url>[^"]+)">patch</a>)'
    r'(?:\s*,\s*signature:\s*|\s*,\s*)(?P<sig_id>[^)]+)\s*\))?'
    r'(?:\s*\(matched from\s+(?P<target_file>[^\s(:]+)'
    r'(?:::(?P<target_function>[^()]+)\(\))?\))?\s*$'
)


@dataclasses.dataclass(frozen=True)
class Report:
  """Dataclass to contain an individual finding to report.

  Each report corresponds to a mapping of one signature and one matched chunk.

  Attributes:
    signature_id: unique ID of the matched signature.
    signature_target_file: original target file of the signature.
    signature_target_function: original target function of the signature.
    signature_source: the source of the patch used to generate the signature.
    unpatched_file: the file matched the signature in the target system.
    unpatched_function_name: the function matched the signature in the target
      system.
    is_non_target_match: whether this matches against a signature's target
      file, or match against other files in the scanned code.
  """

  signature_id: str
  signature_target_file: str
  signature_target_function: str
  signature_source: str
  unpatched_file: str
  unpatched_function_name: str
  is_non_target_match: bool

  def get_simple_report(
      self,
      include_patch_source: bool = False,
      use_html_link_for_patch_source: bool = False,
  ) -> str:
    """Returns unpatched file and optionally unpatched function name."""
    simple_report = self.unpatched_file
    if self.unpatched_function_name:
      simple_report += _FUNC_SUFFIX_FORMAT.format(
          func_name=self.unpatched_function_name
      )

    if include_patch_source:
      if use_html_link_for_patch_source:
        simple_report += _HTML_PATCH_SOURCE_FORMAT.format(
            patch_source=self.signature_source, signature_id=self.signature_id
        )
      else:
        simple_report += _PATCH_SOURCE_FORMAT.format(
            patch_source=self.signature_source, signature_id=self.signature_id
        )

    if self.is_non_target_match:
      source_patched_code = self.signature_target_file
      if self.signature_target_function:
        source_patched_code += _FUNC_SUFFIX_FORMAT.format(
            func_name=self.signature_target_function
        )
      simple_report += _MATCHED_FROM_FORMAT.format(
          target_code=source_patched_code
      )

    return simple_report

  @classmethod
  def from_simple_report(cls, report_str: str) -> Self | None:
    """Parses a simple report string back into a Report instance.

    Args:
      report_str: The raw string representation of a missing patch finding.
        E.g., "target.c::vuln()  (patch:http://patch, signature:test-sig)".

    Returns:
      A parsed Report object, or None if the string was empty or malformed.
      E.g.,
      Report(
          signature_id="test-sig",
          signature_target_file="target.c",
          signature_target_function="vuln",
          signature_source="http://patch",
          unpatched_file="target.c",
          unpatched_function_name="vuln",
          is_non_target_match=False
      )
    """
    report_str = report_str.strip()
    if not report_str:
      return None

    match = _SIMPLE_REPORT_REGEX.match(report_str)
    if not match:
      return None

    unpatched_file = match.group('unpatched_file')
    if not unpatched_file:
      return None

    url_match = match.group('url')
    html_match = match.group('html_url')
    signature_source = (url_match or html_match or '').strip()

    target_file = match.group('target_file')

    return cls(
        signature_id=(match.group('sig_id') or '').strip(),
        signature_target_file=(target_file or '').strip(),
        signature_target_function=(
            match.group('target_function') or ''
        ).strip(),
        signature_source=signature_source,
        unpatched_file=unpatched_file.strip(),
        unpatched_function_name=(
            match.group('unpatched_function') or ''
        ).strip(),
        is_non_target_match=bool(target_file),
    )


@dataclasses.dataclass(frozen=True)
class ReportGroup:
  """Dataclass for managing multiple reports grouped by a vulnerability ID."""

  osv_id: str
  cve_ids: Sequence[str]
  reports: Sequence[Report]


class ReportBook:
  """Class for managing multiple report groups."""

  def __init__(
      self,
      reports: Sequence[Report],
      vul_manager: vulnerability_manager.VulnerabilityManager,
  ):
    """Generates a report book for the given reports."""
    self._report_group_dict = {}
    reports_per_vul = collections.defaultdict(list)
    for report in reports:
      osv_id = vul_manager.sign_id_to_osv_id(report.signature_id)
      reports_per_vul[osv_id].append(report)
    for osv_id, reports in reports_per_vul.items():
      report_group = ReportGroup(
          osv_id, vul_manager.osv_id_to_cve_ids(osv_id), reports
      )
      self._report_group_dict[osv_id] = report_group

  @property
  def unpatched_vulnerabilities(self) -> Sequence[Union[str, None]]:
    """Returns a list of OSV IDs of vulns reported as not patched."""
    return list(self._report_group_dict.keys())

  @functools.cached_property
  def unpatched_cves(self) -> Sequence[str]:
    """Returns a list of CVEs reported as not patched."""
    cves = itertools.chain.from_iterable(
        [rgroup.cve_ids for rgroup in self._report_group_dict.values()]
    )
    return sorted(set(cves))

  def get_report_group(self, osv_id: str) -> Optional[ReportGroup]:
    """Returns a report group mapped to |osv_id|.

    Args:
      osv_id: the OSV ID string.

    Returns:
      Returns a report group mapped to |osv_id| or None if none matches.
    """
    return self._report_group_dict.get(osv_id)


def generate_reports(
    findings: scanner_base.Findings
) -> Sequence[Report]:
  """A helper function to convert a Scanner's Findings to a list of Reports."""
  reports = []
  for sign, chunks in findings.items():
    for chunk in chunks:
      is_non_target_match = not chunk.target_file.endswith(sign.target_file)
      reports.append(
          Report(
              signature_id=sign.signature_id,
              signature_target_file=sign.target_file,
              signature_target_function=getattr(sign, 'target_function', ''),
              signature_source=sign.source,
              unpatched_file=chunk.target_file,
              unpatched_function_name=getattr(chunk.base, 'name', ''),
              is_non_target_match=is_non_target_match,
          )
      )
  return reports
