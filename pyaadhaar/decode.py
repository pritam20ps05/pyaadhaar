from lxml import etree
from io import BytesIO
from typing import Union
from . import utils, verify
import os, base64, zlib
from cryptography import x509

from PIL import Image, ImageFile
ImageFile.LOAD_TRUNCATED_IMAGES = True

class AadhaarSecureQr:
    # This is the class for Aadhaar Secure Qr code..  In this version of code the data is in encrypted format
    # The special thing of this type of QR is that we can extract the photo of user from the data
    # This class now supports current version of Aadhaar QR codes [version-3]
    # For more information check here : https://uidai.gov.in/images/resource/User_manulal_QR_Code_15032019.pdf

    def __init__(self, base10encodedstring:str) -> None:
        self.base10encodedstring = base10encodedstring
        self.details = ["email_mobile_status","referenceid", "name", "dob", "gender", "careof", "district", "landmark",
                        "house", "location", "pincode", "postoffice", "state", "street", "subdistrict", "vtc"]
        self.delimeter = [-1]
        self.data = {}
        self._convert_base10encoded_to_decompressed_array()
        self._check_for_version()  # Check if Vx format exists
        self._create_delimeter()
        self._extract_info_from_decompressed_array()

    # Converts base10encoded string to a decompressed array
    def _convert_base10encoded_to_decompressed_array(self) -> None:
        bytes_array = self.base10encodedstring.to_bytes(5000, 'big').lstrip(b'\x00')
        self.decompressed_array = zlib.decompress(bytes_array, 16+zlib.MAX_WBITS)

    def _check_for_version(self) -> None:
        """Check for Vx version markers (non-standard extension)"""
        version_marker = self.decompressed_array[:2].decode("ISO-8859-1", errors='ignore')
        if version_marker.startswith("V") and version_marker[1].isdigit():
            # If version marker exists, add version and mobile fields
            self.details.insert(0, "version")
            self.details.append("last_4_digits_mobile_no")

    # Creates the delimeter which is used to extract the information from the decompressed array
    def _create_delimeter(self) -> None:
        for i in range(len(self.decompressed_array)):
            if self.decompressed_array[i] == 255:
                self.delimeter.append(i)

    # Extracts the information from the decompressed array
    def _extract_info_from_decompressed_array(self) -> None:
        for i in range(len(self.details)):
            self.data[self.details[i]] = self.decompressed_array[
                self.delimeter[i] + 1:self.delimeter[i+1]
            ].decode("ISO-8859-1")
        
        # Extract last 4 digits of Aadhaar (first 4 chars of referenceId)
        self.data['aadhaar_last_4_digit'] = self.data['referenceid'][:4] if len(self.data['referenceid']) >= 4 else self.data['referenceid']
        
        # Extract last digit of Aadhaar (4th char of referenceId, index 3)
        self.data['aadhaar_last_digit'] = self.data['referenceid'][3] if len(self.data['referenceid']) > 3 else ''
        
        # Set email/mobile flags based on email_mobile_status
        self.data['email'] = int(self.data['email_mobile_status']) in {1, 3}
        self.data['mobile'] = int(self.data['email_mobile_status']) in {2, 3}

    # Returns the extracted data in a dictionary format
    def decodeddata(self) -> dict:
        return self.data

    # Returns signature of the QR code
    def signature(self) -> bytes:
        return self.decompressed_array[len(self.decompressed_array) - 256 :]

    # Returns the signed data of the QR code
    def signedData(self) -> bytes:
        return self.decompressed_array[:len(self.decompressed_array)-256]

    # Check whether mobile no is registered or not
    def isMobileNoRegistered(self) -> bool:
        return self.data['mobile']

    # Check whether email id is registered or not
    def isEmailRegistered(self) -> bool:
        return self.data['email']

    # Return hash of the email id
    def sha256hashOfEMail(self) -> str:
        # V3/V5 format doesn't store email/mobile hashes, only last 4 digits in text field
        if 'version' in self.data and self.data.get('version') in ('V2', 'V3', 'V5'):
            return ""  # V3 format uses text field verification, not hash
        
        tmp = ""
        if int(self.data['email_mobile_status']) == 3:
            # When both present: email is at [len-256-32-32:len-256-32]
            tmp = self.decompressed_array[len(self.decompressed_array)-256-32-32:len(self.decompressed_array)-256-32].hex()
        elif int(self.data['email_mobile_status']) == 1:
            # When only email: email is at [len-256-32:len-256]
            tmp = self.decompressed_array[len(self.decompressed_array)-256-32:len(self.decompressed_array)-256].hex()
        return tmp

    # Return hash of the mobile number
    def sha256hashOfMobileNumber(self) -> str:
        # V3/V5 format doesn't store email/mobile hashes, only last 4 digits in text field
        if 'version' in self.data and self.data.get('version') in ('V2', 'V3', 'V5'):
            return ""  # V3 format uses text field verification, not hash
        
        # When both (3) or only mobile (2): mobile is at [len-256-32:len-256]
        return (
            self.decompressed_array[
                len(self.decompressed_array)
                - 256
                - 32 : len(self.decompressed_array)
                - 256
            ].hex()
            if int(self.data['email_mobile_status']) in {3, 2}
            else ""
        )

    # Check availability of image in the QR CODE
    def isImage(self, buffer = 10) -> bool:
        # V3/V5 format: use last delimiter before version/last_4_digits fields
        # Standard format: use delimiter at len(self.details)
        if 'version' in self.data and self.data.get('version') in ('V2', 'V3', 'V5'):
            # V3 has extra fields, photo ends before signature only (no hash storage)
            last_text_delimiter_idx = len(self.details) - 2 if 'last_4_digits_mobile_no' in self.details else len(self.details) - 1
        else:
            last_text_delimiter_idx = len(self.details)
        
        # For V3, only signature after photo (no hashes)
        if 'version' in self.data and self.data.get('version') in ('V2', 'V3'):
            return (
                len(
                    self.decompressed_array[
                        self.delimeter[last_text_delimiter_idx] + 1 :
                    ]
                )
                >= 256 + buffer
            )
        # Standard format with hash storage
        elif int(self.data['email_mobile_status']) == 3:
            return (
                len(
                    self.decompressed_array[
                        self.delimeter[len(self.details)] + 1 :
                    ]
                )
                >= 256 + 32 + 32 + buffer
            )
        elif int(self.data['email_mobile_status']) in {2, 1}:
            return (
                len(
                    self.decompressed_array[
                        self.delimeter[len(self.details)] + 1 :
                    ]
                )
                >= 256 + 32 + buffer
            )
        elif int(self.data['email_mobile_status']) == 0:
            return (
                len(
                    self.decompressed_array[
                        self.delimeter[len(self.details)] + 1 :
                    ]
                )
                >= 256 + buffer
            )
    
    # Return image stream
    def image(self) -> Union[Image.Image,None]:
        # V3/V5 format: Photo starts after all text fields have been extracted
        if 'version' in self.data and self.data.get('version') in ('V2', 'V3', 'V5'):
            # Photo starts after delimiter at index len(self.details)
            # (fields use delimiters 0 through len-1, photo starts after next delimiter)
            photo_start = self.delimeter[len(self.details)] + 1
            photo_end = len(self.decompressed_array) - 256
            return Image.open(BytesIO(self.decompressed_array[photo_start:photo_end]))
        
        # Standard format with hash storage
        if int(self.data['email_mobile_status']) == 3:
            photo_end = len(self.decompressed_array) - 256 - 32 - 32
            return Image.open(
                BytesIO(
                    self.decompressed_array[
                        self.delimeter[len(self.details)] + 1 : photo_end
                    ]
                )
            )
        elif int(self.data['email_mobile_status']) in {2, 1}:
            photo_end = len(self.decompressed_array) - 256 - 32
            return Image.open(
                BytesIO(
                    self.decompressed_array[
                        self.delimeter[len(self.details)] + 1 : photo_end
                    ]
                )
            )
        elif int(self.data['email_mobile_status']) == 0:
            photo_end = len(self.decompressed_array) - 256
            return Image.open(
                BytesIO(
                    self.decompressed_array[
                        self.delimeter[len(self.details)] + 1 : photo_end
                    ]
                )
            )
        else:
            return None

    # Save the image of the user
    def saveimage(self, filepath:str) -> None:
        image = self.image()
        image.load()
        image.save(filepath)

    # Verify the signature of the QR code
    def verifySignature(self, cert: x509.Certificate | str) -> bool:
        """_Verify QR code signature_

        Args:
            cert (x509.Certificate | str): _Certificate object or path to the certificate file issued by UIDAI_

        Returns:
            bool: _True if the signature is valid, False otherwise_

        True return value means the data in the QR code was issued by the signing authority of the \
        provided certificate and has not been tampered with since issuance.
        """
        if isinstance(cert, str):
            cert = verify.getCertfromFile(cert)
        else:
            if not isinstance(cert, x509.Certificate):
                raise TypeError("cert must be an x509.Certificate object or a path to a certificate file")
        
        public_key = cert.public_key()
        return verify.verifyBypk(self.signedData(), self.signature(), public_key)

    # Verify the email id
    def verifyEmail(self, emailid:str) -> bool:
        if type(emailid) != str:
            raise TypeError("Email id should be string")
        generated_sha_mail = utils.SHAGenerator(emailid, self.data['aadhaar_last_digit'])
        return generated_sha_mail == self.sha256hashOfEMail()

    # Verify the mobile no  
    def verifyMobileNumber(self, mobileno:str) -> bool:
        if type(mobileno) != str:
            raise TypeError("Mobile number should be string")
        
        if ('version' in self.data and self.data.get('version') in ('V5')):
            masked = self.data.get('last_4_digits_mobile_no')

            if not masked or len(masked) < 4 or len(mobileno) < 4:
                return False

            return mobileno[-4:] == masked[-4:]
        
        # Check if V3 format with last_4_digits_mobile_no field
        elif 'last_4_digits_mobile_no' in self.data and self.data.get('last_4_digits_mobile_no'):
            # V3 format: verify by comparing last 4 digits
            return mobileno[-4:] == self.data['last_4_digits_mobile_no']
        else:
            # V2 format or standard: verify by SHA256 hash
            generated_sha_mobile = utils.SHAGenerator(mobileno, self.data['aadhaar_last_digit'])
            return generated_sha_mobile == self.sha256hashOfMobileNumber()


class AadhaarOldQr:
    # This is the class for Aadhaar Normal Qr code..  In this version of code the data is in XML v1.0 format
    # For more information check here : https://103.57.226.101/images/resource/User_manulal_QR_Code_15032019.pdf

    def __init__(self, qrdata) -> None:
        self.qrdata = qrdata
        try:
            self.parsedxml = etree.fromstring(qrdata.encode("utf-8"))
        except etree.XMLSyntaxError as e:
            raise ValueError("Invalid QR XML") from e
        self.data = self.parsedxml.attrib

    def decodeddata(self) -> dict:
        # Will return the decoded datas inn dictionary format
        return self.data


class AadhaarOfflineXML:

    # This is the class for Aadhaar Offline XML
    # The special thing of Offline XML is that we can extract the high quality photo of user from the data
    # For more information check here : https://uidai.gov.in/en/ecosystem/authentication-devices-documents/about-aadhaar-paperless-offline-e-kyc.html

    def __init__(self, file: bytes | str, passcode: str, strict: bool = False) -> None:
        self.XMLDSIG_NS = utils.XMLDSIG_NS
        self.data = {}

        if not passcode:
            raise ValueError("passcode is required when verifying a zipped offline XML")
        self.passcode = passcode
        
        # Extracting raw xml bytes from the file
        filedata = utils.getxmlbytes(file, passcode)

        # Parse the XML data
        try:
            parser = etree.XMLParser(remove_blank_text=True)
            self.root = etree.fromstring(filedata, parser)
        except etree.XMLSyntaxError as e:
            raise ValueError("Invalid XML file") from e
        if self.root.tag != "OfflinePaperlessKyc":
            raise ValueError("Not an Aadhaar OfflinePaperlessKyc XML document")
        
        uid_data = self.root.find(".//UidData")
        self.data = self._build_data(uid_data)

        # Run XML format validation and extract metadata
        self._xml_format_validation(strict)

    # Extract data from uid data within XML
    def _build_data(self, uid_data):
        if uid_data is None:
            raise ValueError("Offline eKYC XML is missing UidData")
        poi = uid_data.find("Poi")
        poa = uid_data.find("Poa")
        photo = uid_data.find("Pht")
        if poi is None or poa is None or photo is None:
            raise ValueError("Offline eKYC XML is missing Poi, Poa, or Pht data")
        reference_id = self.root.get("referenceId", "")
        mobile_hash = poi.get("m", "")
        email_hash = poi.get("e", "")

        data = {
            "referenceid": reference_id,
            "name": poi.get("name", ""),
            "dob": poi.get("dob", ""),
            "gender": poi.get("gender", ""),
            "careof": poa.get("careof", ""),
            "district": poa.get("dist", ""),
            "landmark": poa.get("landmark", ""),
            "house": poa.get("house", ""),
            "location": poa.get("loc", ""),
            "pincode": poa.get("pc", ""),
            "postoffice": poa.get("po", ""),
            "state": poa.get("state", ""),
            "street": poa.get("street", ""),
            "subdistrict": poa.get("subdist", ""),
            "vtc": poa.get("vtc", ""),
            "photo": photo.text or "",
            "mobile_hash": mobile_hash,
            "email_hash": email_hash,
            "aadhaar_last_4_digit": reference_id[:4],
            "aadhaar_last_digit": reference_id[3] if len(reference_id) > 3 else "",
            "mobile": bool(mobile_hash),
            "email": bool(email_hash),
        }
        if data["mobile"] and data["email"]:
            data["email_mobile_status"] = "3"
        elif data["mobile"]:
            data["email_mobile_status"] = "1"
        elif data["email"]:
            data["email_mobile_status"] = "2"
        else:
            data["email_mobile_status"] = "0"
        return data
    
    # Validates XML and extracts metadata
    def _xml_format_validation(self, strict: bool = False) -> None:
        signature_element = self.root.find(f".//{{{self.XMLDSIG_NS}}}Signature")
        if signature_element is None:
            raise ValueError("No XML signature element found")
        
        signed_info = signature_element.find(f"{{{self.XMLDSIG_NS}}}SignedInfo")
        if signed_info is None:
            raise ValueError("Invalid XML signature block")
        
        references = signature_element.findall(f".//{{{self.XMLDSIG_NS}}}Reference")
        if len(references) != 1:
            raise ValueError("XML signature must contain exactly one Reference digest")
        reference = references[0]
        
        digest_value_text = reference.findtext(f"{{{self.XMLDSIG_NS}}}DigestValue")

        # Strict validation of XML format
        if strict:
            signature_method = signed_info.find(f"{{{self.XMLDSIG_NS}}}SignatureMethod")
            signature_algorithm = signature_method.get("Algorithm", "") if signature_method is not None else ""
            if signature_algorithm != f"{self.XMLDSIG_NS}rsa-sha1":
                raise ValueError(f"Unsupported XML signature algorithm: {signature_algorithm or 'undefined'}")
            
            canonicalization_method = signed_info.find(f"{{{self.XMLDSIG_NS}}}CanonicalizationMethod")
            canonicalization_algorithm = canonicalization_method.get("Algorithm", "") if canonicalization_method is not None else ""
            if canonicalization_algorithm != "http://www.w3.org/TR/2001/REC-xml-c14n-20010315":
                raise ValueError(f"Unsupported XML canonicalization algorithm: {canonicalization_algorithm or 'undefined'}")
            
            digest_method = reference.find(f"{{{self.XMLDSIG_NS}}}DigestMethod")
            if digest_method is None or not digest_value_text or not digest_method.get("Algorithm", "").lower().endswith("sha256"):
                raise ValueError("XML signature has an invalid Reference digest")
            
            uri = reference.get("URI", "")
            if uri not in ("", None):
                raise ValueError(f"Unsupported XML signature Reference URI: {uri}")

            transforms = reference.xpath(
                "./ds:Transforms/ds:Transform/@Algorithm",
                namespaces={"ds": self.XMLDSIG_NS},
            )
            if transforms != [f"{self.XMLDSIG_NS}enveloped-signature"]:
                raise ValueError("Unsupported XML signature transform")
        
        # Assigning all extracted metadata
        self.signature_value = utils._clean_base64_text(
            signature_element.findtext(f"{{{self.XMLDSIG_NS}}}SignatureValue")
        )
        self.signed_data = etree.tostring(
            signed_info,
            method="c14n",
            exclusive=True,
            with_comments=False,
        )
        self.digest_value = utils._clean_base64_text(digest_value_text)

    # Get decoded data in dictionary format
    def decodeddata(self) -> dict:
        return self.data

    # Returns b64 encoded signature
    def signature(self) -> str:
        return self.signature_value if self.signature_value else ""
    
    # Returns signed data
    def signedData(self) -> bytes:
        return self.signed_data if self.signed_data else b""

    # Returns SHA256 digest value from XML
    def digestValue(self) -> str:
        return self.digest_value if self.digest_value else ""
    
    # Returns the embedded X.509 certificate from the XML
    def x509Certificate(self):
        return verify.extract_embedded_x509_certificate(self.root)

    # Check if mobile number is registered
    def isMobileNoRegistered(self) -> bool:
        return self.data["mobile"]

    # Check if email id is registered
    def isEmailRegistered(self) -> bool:
        return self.data["email"]

    # Get the hash of email id
    def sha256hashOfEMail(self) -> str:
        return self.data["email_hash"]

    # Get the hash of mobile number
    def sha256hashOfMobileNumber(self) -> str:
        return self.data["mobile_hash"]

    # Get the image of user
    def image(self) -> Image.Image:
        return Image.open(BytesIO(base64.b64decode(self.data["photo"])))

    # Save the image of user
    def saveimage(self, filepath:str) -> None:
        self.image().save(filepath)

    # Verify the uid data against the digest value
    def verifyDigest(self) -> bool:
        target_data = utils.get_verifiable_target(self.root)
        computed_digest = verify.computeDigest(target_data)
        return computed_digest == self.digestValue()
    
    # Verify the signed data against the signature value using a trusted certificate
    def verifySignature(self, cert: x509.Certificate | str) -> bool:
        """_Verify XML signature_  

        #### WARNING: This function only verifies the signature of the XML data, not the digest. \
            Use verifyXML() instead to verify the integrity of the entire XML document.

        Args:
            cert (x509.Certificate | str): _The certificate (either as an x509.Certificate object \
                                            or a path to a certificate file) issued by UIDAI_

        Returns:
            bool: _True if the signature is valid, False otherwise_
        """
        if isinstance(cert, str):
            cert = verify.getCertfromFile(cert)
        else:
            if not isinstance(cert, x509.Certificate):
                raise TypeError("cert must be an x509.Certificate object or a path to a certificate file")

        public_key = cert.public_key()
        return verify.verifyBypk(self.signedData(), 
            base64.b64decode(self.signature()), 
            public_key, hash=1
        )
    
    def verifyXML(self, cert: x509.Certificate | str) -> bool:
        """_Verify the integrity and authenticity of the entire XML document by \
            validating both the digest and the signature._

        Args:
            cert (x509.Certificate | str): _The certificate (either as an x509.Certificate \
                                            object or a path to a certificate file) issued by UIDAI_

        Returns:
            bool: _True if both the digest and signature are valid, False otherwise_

        True return value means the data in the XML was issued by the signing authority of the provided certificate 
        and has not been tampered with since issuance.
        """
        return self.verifyDigest() and self.verifySignature(cert)
    
    def verifyXMLembedded(self) -> bool:
        """_Verify the integrity of XML document against the Certificate embedded in the XML_

        #### WARNING: This function verifies the integrity of the XML data against the embedded certificate. \
            Which cannot be trusted as a trust ancor unless the embedded certificate is verified against a trusted root certificate. \
            Use verifyXML() instead to verify the integrity against a trusted certificate.

        Raises:
            ValueError: _No embedded X.509 certificate found in XML_

        Returns:
            bool: _True if the integrity is valid, False otherwise_
        """
        embedded_cert = self.x509Certificate()
        if embedded_cert is None:
            raise ValueError("No embedded X.509 certificate found in XML")
        
        return self.verifyXML(embedded_cert)

    # Verify the email id
    def verifyEmail(self, emailid:str) -> bool:
        generated_sha_mail = utils.SHAGenerator(str(emailid)+str(self.passcode), self.data['aadhaar_last_digit'])
        return generated_sha_mail == self.sha256hashOfEMail()

    # Verify the mobile number
    def verifyMobileNumber(self, mobileno:str) -> bool:
        generated_sha_mobile = utils.SHAGenerator(str(mobileno)+str(self.passcode), self.data['aadhaar_last_digit'])
        return generated_sha_mobile == self.sha256hashOfMobileNumber()