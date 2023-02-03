import re
import sys
from datetime import datetime, timedelta

import click
import nvdlib
import prettytable


@click.command()
@click.option('--id', required=False, help='Id for CVE, for example: \'CVE-1999-1322\'')
@click.option('--key', required=False, help='Keyword for searching, use \'+\' to input multiple keywords, '
                                            'for example: \'harmonyos+overflow\'.')
@click.option('--date', nargs=2, required=False,
              help='Time range for searching, input two date to represent the start and end, '
                   'and \'0\' for the present. for example: \'2023-10-01 2023-01-01\' or \'2023-01-01 0\'. ')
@click.option('--cwe', required=False, help='CWE for searching, for example: \'CWE-1\' or \'1\'.')
@click.option('--cvss', type=click.Choice(['critical', 'high', 'medium', 'low']), required=False,
              help='CVSS3.1 for searching, the optional range is \'critical\', \'high\', \'medium\' and \'low\'}.')
@click.option('--cvss2', type=click.Choice(['high', 'medium', 'low']), required=False,
              help='CVSS2.0 for searching, the optional range is \'high\', \'medium\' and \'low\'}.')
@click.option('--num', required=True, default=10, type=click.INT,
              help='Display number, the default is 10 and use any number less than or equal to 0 for all.')
@click.option('--csv', type=click.File('a'), required=False, help='Denote the path to save the output as a CSV.')
@click.option('--api', required=False, envvar='NVD_KEY',
              help='The NVD API KEY helps you get higher query frequency. You can apply from'
                   ' \'https://nvd.nist.gov/developers/request-an-api-key\' and then set the key manually or put it in '
                   'an environment variable named \'NVD_KEY\'.')
def search(id, key, date, cwe, cvss, cvss2, num, csv, api):
    table = prettytable.PrettyTable(['CVE-ID', 'CWE', 'description',
                                     'score', 'severity', 'vector', 'version', 'references', 'cpe', 'pub'])
    table.hrules = prettytable.ALL

    table.max_width = 28

    cves = []
    if id:
        crt_cves = nvdlib.searchCVE(cveId=id, key=api)
        if len(cves):
            cves.append(crt_cves[0])
    else:
        if key:
            key = key.replace('+', ' ')
        if cwe and re.match(r'\d+', cwe):
            cwe = 'CWE-{}'.format(cwe)
        elif cwe and not re.match(r'CWE-\d+', cwe):
            err('CWE input is wrong, the correct format is such as \'1\', \'CWE-1\'')
        if cvss and cvss2:
            err('Option cvss and cvss2 cannot be used at the same time')
        time_range = [(None, None)]
        if date:
            try:
                start = datetime.strptime(date[0], '%Y-%m-%d')
                if date[1] == '0':
                    end = datetime.today()
                else:
                    end = datetime.strptime(date[1], '%Y-%m-%d')
                if end <= start:
                    err('End should be larger than start.')
                time_range.clear()
                while start < end:
                    next_start = min(start + timedelta(days=120), end)
                    time_range.append((start, next_start))
                    start = next_start
            except ValueError:
                err('Time input is wrong, the correct format is such as \'0\', \'2000-01-01\'')
        for start, end in time_range:
            limit = None
            if 0 < num - len(cves) < 2000:
                limit = num - len(cves)
            elif num <= len(cves):
                break
            crt_cves = nvdlib.searchCVE(keywordSearch=key, cvssV3Severity=cvss, cvssV2Severity=cvss2, cweId=cwe,
                                        limit=limit,
                                        pubStartDate=start, pubEndDate=end, key=api)
            cves.extend(crt_cves)
        if num > 0:
            cves = cves[:num]
    for cve in cves:
        for r in parse(cve):
            table.add_row(r)

    rows = table.rows
    if len(rows):
        click.echo('A total of {} CVEs were found'.format(len(cves)))
        if len(rows) > 10:
            click.echo('There are only up to ten lines shown here, if you need to see more, use --csv')
        click.echo(table[:min(10, len(rows))])
        if csv and csv.tell():
            for row in rows:
                for i in (1, 2, 6, 7, 8):
                    row[i] = "\"{}\"".format(row[i])
                csv.write(','.join(row) + '\n')
        elif csv:
            csv.write(table.get_csv_string())
        click.pause()
        return
    err('No results found under restrictions')


score_eds = ['v2', 'v3', 'v31']


def parse(cve):
    desc = cve.descriptions[0].value
    cwe = ','.join(map(lambda a: a.value, getattr(cve, 'cwe', [])))
    references = ','.join(map(lambda a: a.url, getattr(cve, 'references', [])))
    cpe = ','.join(map(lambda a: a.criteria, getattr(cve, 'cpe', [])))
    if str(desc).startswith('** REJECT **'):
        return []
    res = []
    for ed in list(filter(lambda ed: getattr(cve, '{}score'.format(ed), ''), score_eds)):
        res.append(
            (cve.id, cwe, desc, getattr(cve, '{}score'.format(ed), ''), getattr(cve, '{}severity'.format(ed), ''),
             getattr(cve, '{}vector'.format(ed), ''), ed, references, cpe, getattr(cve, 'published', '')))
    if len(res) == 0:
        res.append((cve.id, cwe, desc, '', '', '', '', references, cpe, getattr(cve, 'published', '')))
    return res


def err(msg):
    click.secho('[Error] {}'.format(msg), fg='red')
    click.pause()
    sys.exit()


if __name__ == '__main__':
    search()
