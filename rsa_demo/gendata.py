'''
Generate paragraphs of random data with bogus goals and catchphrases.

This data can be used as input to encrypt and decrypt operations.
'''
import argparse
import os
import random
import sys
import textwrap

import faker
from faker import Faker

# Is the sys.path.append really needed?
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
from rsa_demo import __version__


def getopts() -> argparse.Namespace:
    '''
    Get the command line options.
    '''
    def gettext(string):
        '''
        Convert to upper case to make things consistent.
        '''
        lookup = {
            'usage: ': 'USAGE:',
            'positional arguments': 'POSITIONAL ARGUMENTS',
            'optional arguments': 'OPTIONAL ARGUMENTS',
            'show this help message and exit': 'Show this help message and exit.\n ',
        }
        return lookup.get(string, string)

    argparse._ = gettext  # to capitalize help headers
    base = os.path.basename(sys.argv[0])
    #name = os.path.splitext(base)[0]
    usage = '\n  {0} [OPTIONS]'.format(base)
    desc = 'DESCRIPTION:{0}'.format('\n  '.join(__doc__.split('\n')))
    epilog = f'''\
EXAMPLES:
    # Example 1: help
    $ {base} --help

    # Example 2: Generate random data.
    $ {base}

    # Example 3: Generate 20 paragraphs of random data.
    $ {base} -p 20

    # Example 4: Generate 20 paragraphs of random data to a file.
    $ {base} -p 20 > file.txt
    $ {base} -p 20 -o file.txt
'''

    afc = argparse.RawTextHelpFormatter
    parser = argparse.ArgumentParser(formatter_class=afc,
                                     description=desc[:-2],
                                     usage=usage,
                                     epilog=epilog + ' \n')

    parser.add_argument('-p', '--num-paragraphs',
                        action='store',
                        type=int,
                        metavar=('INT'),
                        help='''\
The number of paragraphs to generate.
The default is a random number between 4 and 20.

''')

    parser.add_argument('-P', '--num-paragraph-sentences',
                        action='store',
                        nargs=2,
                        type=int,
                        default=[3, 8],
                        metavar=('INT', 'INT'),
                        help='''\
Number of sentences per paragraph: min and max.
Default: %(default)s
''')

    parser.add_argument('-o', '--output',
                        action='store',
                        type=str,
                        metavar=('FILE'),
                        help='''\
Output file.
If not specified, the default is stdout.

''')

    parser.add_argument('-s', '--seed',
                        action='store',
                        type=int,
                        help='''\
Specify a random seed. This helps with demo's but
is not at all secure.

''')

    parser.add_argument('-v', '--verbose',
                        action='count',
                        default=0,
                        help='''\
Output a lot of information about the intermediate steps.

''')

    parser.add_argument('-V', '--version',
                        action='version',
                        version='%(prog)s version {0}'.format(__version__),
                        help='''\
Show program's version number and exit.

''')

    parser.add_argument('-w', '--width',
                        action='store',
                        type=int,
                        default=72,
                        metavar=('INT'),
                        help='''\
Line width.
Default: %(default)s.
''')

    opts = parser.parse_args()
    return opts


def main():
    '''
    Generate random data.
    '''
    opts = getopts()
    if opts.seed:
        random.seed(opts.seed)

    if opts.num_paragraphs:
        num = opts.num_paragraphs
    else:
        num = random.randint(4, 20)

    ofp = sys.stdout
    if opts.output:
        ofp = open(opts.output, 'w')


    fake = Faker()
    fake.add_provider(faker.providers.company)
    fake.add_provider(faker.providers.geo)
    fake.add_provider(faker.providers.internet)
    fake.add_provider(faker.providers.lorem)
    fake.add_provider(faker.providers.misc)
    fake.add_provider(faker.providers.person)

    ofp.write(f'{fake.company()}\n')
    ofp.write(f'{fake.catch_phrase()}\n')
    ofp.write('\n')
    ofp.write(f'Goal: {fake.bs()}\n')
    smin = opts.num_paragraph_sentences[0]
    smax = opts.num_paragraph_sentences[1]
    for _ in range(num):
        ofp.write('\n')
        num_sentences = random.randint(smin, smax)
        text = fake.paragraph(nb_sentences=num_sentences)
        wtext = textwrap.wrap(text, opts.width)
        ofp.write('\n'.join(wtext) + '\n')

    if opts.output:
        ofp.close()


if __name__ == '__main__':
    main()
