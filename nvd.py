import re
import sys
from datetime import datetime

import click
import nvdlib
import prettytable


@click.command()
@click.option('--id', required=False, help='Id for CVE, for example: \'CVE-1999-1322\'')
@click.option('--key', required=False, help='Keyword for searching, use \'+\' to input multiple keywords, '
                                            'for example: \'harmonyos+overflow\'.')
@click.option('--date', nargs=2, required=False,
              help='Time range for searching, input two date to represent the start and end, '
                   'and \'0\' for the present. for example: \'2023-10-01 2023-01-01\' or \'2023-01-01 0\'. '
                   'Note that the interval between the two dates should be less than 120 days.')
@click.option('--cwe', required=False, help='CWE for searching, for example: \'CWE-1\' or \'1\'.')
@click.option('--cvss', type=click.Choice(['critical', 'high', 'medium', 'low']), required=False,
              help='CVSS3.1 for searching, the optional range is \'critical\', \'high\', \'medium\' and \'low\'}.')
@click.option('--num', required=True, default=10, help='Display number, the default is 10 and use \'-1\' for all.')
@click.option('--csv', type=click.File('a'), required=False, help='Denote the path to save the output as a CSV.')
@click.option('--api', required=False, envvar='NVD_KEY',
              help='The NVD API KEY helps you get higher query frequency. You can apply from'
                   ' \'https://nvd.nist.gov/developers/request-an-api-key\' and then set the key manually or put it in '
                   'an environment variable named \'NVD_KEY\'.')
def search(id, key, date, cwe, cvss, num, csv, api):
    table = prettytable.PrettyTable(['CVE-ID', 'CWE', 'description',
                                     'score', 'severity', 'vector', 'references', 'cpe'])
    table.hrules = prettytable.ALL
    table.max_width = 28

    if id:
        cves = nvdlib.searchCVE(cveId=id, key=api)
        if len(cves):
            table.add_row(parse(cves[0]))
    else:
        if key:
            key = key.replace('+', ' ')
        if cwe and re.match(r'\d+', cwe):
            cwe = 'CWE-{}'.format(cwe)
        elif cwe and not re.match(r'CWE-\d+', cwe):
            err('CWE input is wrong, the correct format is such as \'1\', \'CWE-1\'')
        start, end = None, None
        if date:
            try:
                start = datetime.strptime(date[0], '%Y-%m-%d')
                if date[1] == '0':
                    end = datetime.today()
                else:
                    end = datetime.strptime(date[1], '%Y-%m-%d')
                if end <= start:
                    err('End should be larger than start.')
                if (end - start).days > 120:
                    err('E.The interval between the two dates should be less than 120 days.')
            except ValueError:
                err('Time input is wrong, the correct format is such as \'0\', \'2000-01-01\'')
        if num == -1:
            num = None
        if num > 2000:
            err('The maximum of number is 2000, is you want to find more CVEs, use \'-1\' to see all.')
        cves = nvdlib.searchCVE(keywordSearch=key, cvssV3Severity=cvss, cweId=cwe, limit=num,
                                pubStartDate=start, pubEndDate=end, key=api)
        for cve in cves:
            table.add_row(parse(cve))
    rows = table.rows
    if len(rows):
        click.echo('A total of {} CVEs were found'.format(len(rows)))
        if len(rows) > 10:
            click.echo('There are only up to ten items shown here, if you need to see more, use --csv')
        click.echo(table[:min(10, len(rows))])
        if csv and csv.tell():
            for row in rows:
                for i in (2, 3, 7, 8):
                    row[i] = "\"{}\"".format(row[i])
                csv.write(','.join(row) + '\n')
        elif csv:
            csv.write(table.get_csv_string())
        click.pause()
        return
    err('No results found under restrictions')


def parse(cve):
    desc = cve.descriptions[0].value
    cwe = ','.join(map(lambda a: a.value, getattr(cve, 'cwe', [])))
    references = ','.join(map(lambda a: a.url, getattr(cve, 'references', [])))
    cpe = ','.join(map(lambda a: a.criteria, getattr(cve, 'cpe', [])))
    return (cve.id, cwe, desc, getattr(cve, 'v31score', ''), getattr(cve, 'v31severity', ''),
            getattr(cve, 'v31vector', ''), references, cpe)


def err(msg):
    click.secho('[Error] {}'.format(msg), fg='red')
    click.pause()
    sys.exit()


if __name__ == '__main__':
    search()