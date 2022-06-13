import get_pdg
import glob
import os
import json
import argparse

from vulnerability_detection import load_sensitive_apis, analyze_extension_part, analyze_vulnerabilities
import danger_analysis
import wa_communication

def main():
    """ Parsing command line parameters. """

    parser = argparse.ArgumentParser(prog='dxnode',
                                     formatter_class=argparse.RawTextHelpFormatter,
                                     description="Static analysis of a nodejs package to detect "
                                                 "suspicious data flows")

    parser.add_argument("-d", "--dir", dest='dir', metavar="path", type=str, default="../data/30_backstabber_samples/conventional-changelog_1.1.12-->1.2.0/",
                        help="path to the extension directory"
                             "Default for background: empty/background.js (i.e., empty JS file)")

    parser.add_argument("--analysis", metavar="path", type=str,
                        help="path of the file to store the analysis results in. "
                             "Default: parent-path-of-content-script/analysis.json")
    parser.add_argument("--apis", metavar="str", type=str, default='node',
                        help='''specify the sensitive APIs to consider for the analysis:
    - 'node': consider only nodejs apis. (default)
    - 'all': DoubleX selected APIs irrespective of the extension permissions;
    - 'empoweb': APIs from the EmPoWeb paper; to use ONLY on the EmPoWeb ground-truth dataset;
    - path: APIs listed in the corresponding json file; a template can be found in src/suspicious_apis/README.md.''')

    # TODO: control verbosity of logging?

    args = parser.parse_args()

    js_files = glob.glob(os.path.join(args.dir,'**', '*.js'))
    with_benchmarks = [(path, {}) for path in js_files]

    for f, bm in with_benchmarks:
    #pdgs = [(get_pdg.get_pdg(f, bm), bm, {'extension': f}) for (f, bm) in with_benchmarks]
        pdg, res_dict = (get_pdg.get_pdg(f, bm), {'extension': f})

        apis_bench = {}
        apis = load_sensitive_apis(args.apis, None, None, apis_bench)

        extension = danger_analysis.Extension(apis=apis)
        with_wa = wa_communication.WaCommunication()  # Elts coming from/to WA, initialization
        cs = extension.cs
    #for pdg_tuple in pdgs:
        #pdg, bms, res_dict = pdg_tuple
        analyze_extension_part(pdg, whoami='cs', with_wa=with_wa, extension_part=cs,
                                    benchmarks=bm, chrome=False,
                                    messages_dict={})
        analyze_vulnerabilities('cs', res_dict=res_dict, with_wa=with_wa, dangers=cs.dangers,
                                        benchmarks=bm)
        print(json.dumps(res_dict, indent=4, sort_keys=False, skipkeys=True))

    #analyze_extension(cs, bp, json_analysis=args.analysis, chrome=not args.not_chrome,
    #                  war=args.war, json_apis=args.apis, manifest_path=args.manifest)
    print(apis_bench)


if __name__ == "__main__":
    main()
