from hashlib import sha256
import pyaadhaar
import cv2, os, zipfile, io
import numpy as np
from copy import deepcopy
from lxml import etree
from pyzbar.pyzbar import decode

XMLDSIG_NS = "http://www.w3.org/2000/09/xmldsig#"

def SHAGenerator(string, n):
    # This function is to generate the hash for given emailid and mobile

    # To verify mobile/email, first obtain the fourth digit of reference id (last
    # digit of Aadhaar number). If it is 0 or 1 then converts provided Input
    # mobile/mail id into sha256 value of provide data. In case of 2 to 9 convert
    # the sha256 value for same number of times. This converted value should
    # match with the value received in 8. If value not matching means
    # mobile/email not verified.

    # For more read here : https://103.57.226.101/images/resource/User_manulal_QR_Code_15032019.pdf

    tmp_sha = str(string)
    if int(n) == 0 or int(n) == 1:
        return sha256(tmp_sha.encode()).hexdigest()
    for i in range(int(n)):
        tmp_sha = sha256(tmp_sha.encode()).hexdigest()
    return tmp_sha


def isSecureQr(sample):

    # This functioin will return "True" if it is a newly release secure qr code
    # Will return "False" if it is old adhaar qr codes

    try:
        int(sample)
        return True
    except ValueError:
        return False


def AadhaarQrAuto(data):

    # This fuunction will first check the type of qrcode and will
    # create the object of respective class and will return the oobject

    if isSecureQr(data):
        return pyaadhaar.decode.AdhaarSecureQr(int(data))
    else:
        return pyaadhaar.decode.AadhaarOldQr(data)


def Qr_img_to_text(file):
    # This function will extract all qr codes data from image
    # And will return a list of data of all qr codes

    img = cv2.imread(file)
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    code = decode(gray)
    totaldata = []
    for i in code:
        decodeddata = i.data.decode('utf-8')
        totaldata.append(decodeddata)
    return totaldata


# Utility functions for XML

def getxmlbytes(xml: bytes | str, passcode: str) -> bytes:
    """ Extracting raw xml bytes from the file or zip archive (supports both .xml and password-protected .zip containing .xml)
    """

    if isinstance(xml, str):
        if not os.path.isfile(xml):
            raise FileNotFoundError(f"File not found: {xml}")
        
        extension = os.path.splitext(xml)[1].lower()
        if ".zip" == extension:
            # Need to pass the zip file and passcode/sharecode to this function
            try:
                return _getxmlbytes_from_zip(xml, passcode)
            except RuntimeError as e:
                raise ValueError("Could not open ZIP archive. The share code/passcode may be incorrect.") from e
            except zipfile.BadZipFile as e:
                raise ValueError("Unsupported or corrupted ZIP archive") from e

        elif ".xml" == extension:
            with open(xml, "rb") as f:
                return f.read()
    elif isinstance(xml, bytes):
        try:
            return _getxmlbytes_from_zip(io.BytesIO(xml), passcode)
        except:
            return xml
    else:
        raise ValueError("Unsupported offline eKYC file type. Provide a .xml file or a password-protected .zip file.")

def get_verifiable_target(root) -> bytes:
    """ This function returns the canonicalized bytes of the XML data.
    ```
        <OfflinePaperlessKyc>
        <UidData> ... </UidData>
        </OfflinePaperlessKyc>
    ```
    The <Signature> node gets removed from the XML data before canonicalization.
    """

    target = deepcopy(root)
    
    # removes the <Signature> node
    target.remove(target.find(f".//{{{XMLDSIG_NS}}}Signature"))

    return etree.tostring(
        target,
        method="c14n",
        exclusive=True,
        with_comments=False,
    )

def _getxmlbytes_from_zip(zip: io.BytesIO | str, passcode: str) -> bytes:
    """ Extracts the XML bytes from a password-protected ZIP archive. """
    with zipfile.ZipFile(zip, "r") as zf:
        xml_names = [name for name in zf.namelist() if name.lower().endswith(".xml")]
        if not xml_names:
            raise ValueError("ZIP archive does not contain an XML file")
        zf.setpassword(str(passcode).encode("utf-8"))
        return zf.read(xml_names[0])

def _clean_base64_text(text: str) -> str:
    return "".join((text or "").replace("\\n", "").replace("\\r", "").replace("\\t", "").split())