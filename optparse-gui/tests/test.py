import sys
import optparse
import optparse_gui

def main():
    usage = "usage: %prog [options] args"
    if 1 == len( sys.argv ):
        option_parser_class = optparse_gui.OptionParser
    else:
        option_parser_class = optparse.OptionParser
        
    parser = option_parser_class( usage = usage, version='0.1' )
    parser.add_option("-f", "--file", dest="filename", default = r'c:\sample.txt',
                      help="read data from FILENAME")
    parser.add_option("-a", "--action", dest="action",
                      choices = ['delete', 'copy', 'move'],
                      help="Which action do you wish to take?!")
    parser.add_option("-n", "--number", dest="number", default = 23,
                      type = 'int',
                      help="Just a number")
    parser.add_option("-v", "--verbose",
                      action="store_true", dest="verbose",
                      help = 'To be or not to be? ( verbose )')
    
    options, args = parser.parse_args()

    print 'args: %s' % args
    print 'options: %s' % options

if '__main__' == __name__:
    main()
