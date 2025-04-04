import dns.resolver # dnspython
import argparse
import re
from typing import Optional, Dict

class Spoofability:

	def __init__(self, domain: str):

		self.domain = domain.lower().strip()
		self.results = {}

	def check_spf(self) -> None:

		try:

			answers = dns.resolver.resolve(self.domain, 'TXT')
			spf_record = None

			for rdata in answers:

				record = rdata.to_text().strip('"')

				if record.startswith('v=spf1'):

					spf_record = record
					break

			if not spf_record:

				self.results['spf'] = {
					'exists': False,
					'details': 'No SPF record found. This domain is vulnerable to spoofing as there are no sender verification rules.'
				}

				return

			mechanisms = spf_record.split()
			has_all = '-all' in mechanisms
			has_redirect = any(m.startswith('redirect=') for m in mechanisms)
			include_count = sum(1 for m in mechanisms if m.startswith('include:'))

			analysis = []

			if has_all:

				analysis.append('Strong SPF policy (-all) detected: Rejects unauthorized senders')

			elif '+all' in mechanisms:

				analysis.append('\033[31mWARNING: Weak SPF policy (+all) allows all senders - highly spoofable\033[0m')

			elif '~all' in mechanisms:

				analysis.append('SoftFail (~all) policy: Unauthorized senders marked but not rejected')

			if include_count > 5:

				analysis.append(f'\033[31mWARNING: {include_count} includes detected - might exceed DNS lookup limits\033[0m')

			self.results['spf'] = {
				'exists': True,
				'record': spf_record,
				'details': ' | '.join(analysis) if analysis else 'Valid SPF record found'
			}

		except dns.resolver.NXDOMAIN:

			self.results['spf'] = {'exists': False, 'details': 'Domain does not exist'}

		except Exception as e:

			self.results['spf'] = {'exists': False, 'details': f'Error checking SPF: {str(e)}'}

	def check_dkim(self) -> None:

		common_selectors = ['default', 'google', 'mail', 'dkim', 'selector1']
		dkim_results = []

		for selector in common_selectors:
			try:

				dkim_domain = f'{selector}._domainkey.{self.domain}'
				answers = dns.resolver.resolve(dkim_domain, 'TXT')

				for rdata in answers:

					record = rdata.to_text().strip('"')

					if record.startswith('v=DKIM1'):
						dkim_results.append({
							'selector': selector,
							'record': record,
							'valid': 'k=rsa' in record and 'p=' in record
						})

			except dns.resolver.NoAnswer:
				continue

			except dns.resolver.NXDOMAIN:
				continue

		if not dkim_results:

			self.results['dkim'] = {
				'exists': False,
				'details': 'No DKIM records found with common selectors. Email authenticity cannot be verified.'
			}

		else:

			analysis = [f'Found {len(dkim_results)} DKIM record(s)']

			for result in dkim_results:

				status = 'Valid' if result['valid'] else 'Invalid'
				analysis.append(f"Selector '{result['selector']}': {status}")

			self.results['dkim'] = {
				'exists': True,
				'details': ' | '.join(analysis),
				'records': dkim_results
			}

	def check_dmarc(self) -> None:

		try:

			dmarc_domain = f'_dmarc.{self.domain}'
			answers = dns.resolver.resolve(dmarc_domain, 'TXT')
			dmarc_record = None

			for rdata in answers:

				record = rdata.to_text().strip('"')

				if record.startswith('v=DMARC1'):

					dmarc_record = record
					break

			if not dmarc_record:

				self.results['dmarc'] = {
					'exists': False,
					'details': 'No DMARC record found. Domain is vulnerable to spoofing and impersonation.'
				}

				return

			components = dict(re.findall(r'(\w+)=([^;]+)', dmarc_record))
			policy = components.get('p', 'none')
			subdomain_policy = components.get('sp', policy)
			pct = components.get('pct', '100')

			analysis = []

			if policy == 'none':

				analysis.append('\033[31mWARNING: Primary policy=none allows spoofing (monitoring mode only)\033[0m')

			elif policy == 'quarantine':

				analysis.append('Primary policy=quarantine: Suspicious emails marked as spam')

			elif policy == 'reject':

				analysis.append('Primary policy=reject: Spoofed emails blocked')

			if subdomain_policy != policy:

				analysis.append(f'Subdomain policy differs: {subdomain_policy}')

				if subdomain_policy == 'none':

					analysis.append('\033[31mWARNING: sp=none leaves subdomains vulnerable to spoofing - no action taken on failures\033[0m')

				elif subdomain_policy == 'quarantine':

					analysis.append('Subdomain policy=quarantine: Less strict than primary policy' if policy == 'reject' else 'Subdomains moderately protected')

				elif subdomain_policy == 'reject':

					analysis.append('Subdomain policy=reject: Stronger than primary policy' if policy in ['none', 'quarantine'] else 'Subdomains equally protected')

			else:

				analysis.append(f'Subdomain policy matches primary: {subdomain_policy}')

			if pct != '100':

				analysis.append(f'\033[31mWARNING: Only {pct}% of emails protected - partial coverage reduces effectiveness\033[0m')

			if '.' in self.domain:

				parent_domain = '.'.join(self.domain.split('.')[-2:])

				if parent_domain != self.domain:

					try:

						parent_dmarc = f'_dmarc.{parent_domain}'
						dns.resolver.resolve(parent_dmarc, 'TXT')
						analysis.append('Parent domain has DMARC - may override subdomain policy if stricter')

					except dns.resolver.NoAnswer:

						analysis.append('No parent DMARC - subdomains rely on this policy')

			self.results['dmarc'] = {
				'exists': True,
				'record': dmarc_record,
				'details': ' | '.join(analysis) if analysis else 'Valid DMARC record found with consistent policies'
			}

		except dns.resolver.NoAnswer:

			self.results['dmarc'] = {'exists': False, 'details': 'No DMARC record found'}

		except Exception as e:

			self.results['dmarc'] = {'exists': False, 'details': f'Error checking DMARC: {str(e)}'}

	def assess_spoofability(self) -> Dict:

		spf = self.results.get('spf', {})
		dkim = self.results.get('dkim', {})
		dmarc = self.results.get('dmarc', {})

		risk_score = 0
		risk_factors = []

		if not spf.get('exists'):

			risk_score += 40
			risk_factors.append("No SPF: No sender validation")

		elif '+all' in spf.get('record', ''):

			risk_score += 30
			risk_factors.append("SPF +all: Allows all senders")

		elif '~all' in spf.get('record', '') and not dmarc.get('exists'):

			risk_score += 20
			risk_factors.append("SPF ~all without DMARC: Weak enforcement")

		if not dkim.get('exists'):

			risk_score += 30
			risk_factors.append("No DKIM: No email signing")

		elif not any(r['valid'] for r in dkim.get('records', [])):

			risk_score += 20
			risk_factors.append("Invalid DKIM records: Signing ineffective")

		if not dmarc.get('exists'):

			risk_score += 50
			risk_factors.append("No DMARC: No policy enforcement")

		else:

			record = dmarc.get('record', '')
			policy_match = re.search(r'p=(\w+)', record)
			policy = policy_match.group(1) if policy_match else 'none'

			subdomain_policy_match = re.search(r'sp=(\w+)', record)
			subdomain_policy = subdomain_policy_match.group(1) if subdomain_policy_match else policy

			pct_match = re.search(r'pct=(\d+)', record)
			pct = pct_match.group(1) if pct_match else '100'

			if policy == 'none':

				risk_score += 40
				risk_factors.append("DMARC p=none: No protection")

			elif policy == 'quarantine':

				risk_score += 10
				risk_factors.append("DMARC p=quarantine: Partial protection")

			if subdomain_policy == 'none':

				risk_score += 20
				risk_factors.append("DMARC sp=none: Subdomains unprotected")

			if pct != '100':

				risk_score += 10
				risk_factors.append(f"DMARC pct={pct}: Incomplete coverage")

		if risk_score >= 70:

			risk_level = "High"
			summary = "Domain is highly vulnerable to spoofing."

		elif risk_score >= 30:

			risk_level = "Medium"
			summary = "Domain has moderate spoofing risk."

		else:

			risk_level = "Low"
			summary = "Domain is well-protected against spoofing."

		return {
			'risk_level': risk_level,
			'risk_score': risk_score,
			'summary': summary,
			'factors': risk_factors
		}

	def run_checks(self) -> Dict:

		print(f"\nAnalyzing email security for {self.domain}...\n")

		self.check_spf()
		self.check_dkim()
		self.check_dmarc()

		for check, result in self.results.items():

			print(f"{check.upper()} Analysis:")
			print(f"Status: {'Present' if result['exists'] else 'Not Found'}")
			print(f"Details: {result['details']}")

			if 'record' in result:

				print(f"Record: {result['record']}")

			print("-" * 50)

		spoofability = self.assess_spoofability()
		print("\nSpoofability Assessment:")
		print(f"Risk Level: {spoofability['risk_level']} (Score: {spoofability['risk_score']})")
		print(f"Summary: {spoofability['summary']}")

		if spoofability['factors']:

			print("Contributing Factors:")

			for factor in spoofability['factors']:

				print(f"- {factor}")

		print("-" * 50)

		combined_results = self.results.copy()
		combined_results['spoofability'] = spoofability

		return combined_results


if __name__ == "__main__":

	parser = argparse.ArgumentParser(description='Check email domain security configurations')
	parser.add_argument('domain', help='Target domain (e.g., example.com)')
	args = parser.parse_args()

	checker = Spoofability(args.domain)
	checker.run_checks()
