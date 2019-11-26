from pycrate_asn1dir import TCAP_MAPv2v3
import pycrate_core
import pycrate_asn1rt
from pythonfuzz.main import PythonFuzz


@PythonFuzz
def fuzz(buf):
    buf = bytes(buf)
    try:
        M = TCAP_MAPv2v3.TCAP_MAP_Messages.TCAP_MAP_Message
        M.from_ber(buf)
        r = M.to_asn1()
    except pycrate_core.charpy.CharpyErr:
        pass
    except pycrate_asn1rt.err.ASN1BERDecodeErr:
        pass
    except pycrate_core.utils_py3.PycrateErr:
        pass
    except AssertionError:
        pass

if __name__ == '__main__':
    fuzz()
