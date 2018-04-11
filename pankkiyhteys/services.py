from datetime import datetime, timezone

from .messages import ApplicationRequest, CertApplicationRequest, Response
from .utils import SOFTWARE_ID

import random
import logging


class Services:
    CERT_SERVICE = 'cert'
    WEB_SERVICE = 'web'


class BaseMixin:
    """
    Mixin base class.

    This base class offers tools for implementing service mixins.

    Mixins using this base class are designed to be added to derivatives
    of Pankkiyhteys class.
    """

    def _request_id(self):
        """
        Request id generator.

        Returns:
            str: Request id. YYMMDDXXXXXXX where X is random number
                between [0000001-9999999]
        """
        def generator():
            today = value = 0
            while True:
                if today != datetime.utcnow().date():
                    value = random.randint(0, 9999999)
                    today = datetime.utcnow().date()
                value = (value + 1) % 100000
                yield today.strftime('%y%m%d{0}').format(value)

        if not hasattr(self, '_request_id_gen'):
            self._request_id_gen = generator()

        return next(self._request_id_gen)


class CertServiceMixin(BaseMixin):
    """
    Add certificate service functionality
    """

    def __handle_response(self, response):
        response = Response(
            response.ResponseHeader,
            response.ApplicationResponse)

        self.logger.info('Response %s (%s)',
                         response.response_text, response.response_code)

        # Validate signature
        response.verify()

        return response.deserialize()

    def __make_request(self, operation, *, sign=False, **kwargs):
        self.logger.info('%s service: %s',
                         Services.CERT_SERVICE.capitalize(), operation)

        client = self.get_client(Services.CERT_SERVICE)

        RequestHeader = client.get_type('ns0:CertificateRequestHeader')

        header = RequestHeader(
            SenderId=self.username,
            RequestId=self._request_id(),
            Timestamp=datetime.now(timezone.utc))

        request = CertApplicationRequest(
            customer_id=self.username,
            timestamp=datetime.now(timezone.utc),
            environment=self.environment.name,
            software_id=SOFTWARE_ID,
            **kwargs
        )

        # Sign request
        if sign:
            request.sign(self.key)

        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug(
                'Sending request:\n%s',
                request.to_string(pretty_print=True).decode())

        response = getattr(client.service, operation)(
            header, request.to_string())

        return self.__handle_response(response)

    def certify(self, key, *, transfer_key=None):
        """
        Request signed certificate from bank key service

        Some banks require new private key each time a certificate is
        requested.

        Args:
            key (bytes|file): RSA key to certify
            transfer_key (str, optional): 16 digit one-time key required to
                prove identity when requesting the first certificate. User
                must register with the bank to get this key. Transfer key must
                be used if no valid certificate is available, othervise the
                existing certificate can used to to prove identity.

        Raises:
            Exception: Unable to load key
            Exception: Communication error

        Returns:
            bytes: Certificate from the bank. Make sure to save the
                certificate to persistent storage
        """

    def get_service_certificates(self):
        """
        Get service certificates
        """

        return self.__make_request('getServiceCertificates')


class WebServiceMixin(BaseMixin):
    """
    Add web service functionality
    """

    def __handle_response(self, response):
        response = Response(
            response.ResponseHeader,
            response.ApplicationResponse)

        self.logger.info('Response %s (%s)',
                         response.response_text, response.response_code)

        # Validate signature
        response.verify()

        return response.deserialize()

    def __make_request(self, operation, **kwargs):
        self.logger.info('%s service: %s',
                         Services.WEB_SERVICE.capitalize(), operation)

        client = self.get_client(Services.WEB_SERVICE)

        RequestHeader = client.get_type('ns0:RequestHeader')
        header = RequestHeader(
            SenderId=self.username,
            RequestId=self._request_id(),
            Timestamp=datetime.now(timezone.utc),
            Language=self.language,
            UserAgent=SOFTWARE_ID,
            ReceiverId=self.bic)

        request = ApplicationRequest(
            customer_id=self.username,
            timestamp=datetime.now(timezone.utc),
            environment=self.environment.name,
            software_id=SOFTWARE_ID,
            **kwargs
        )

        request.sign(self.key)

        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug(
                'Sending request:\n%s',
                request.to_string(pretty_print=True).decode())

        response = getattr(client.service, operation)(
            header, request.to_string())

        return self.__handle_response(response)

    def get_file(self, file_reference):
        """Download single file

        This operation requires that the customer has obtained file reference
        with ``get_file_list`` or by other means. This file reference is used
        to identify the exact file to be downloaded.

        Args:
            file_reference (str): Identification of the file that is the
            target of the operation.
        """
        return self.__make_request(
            'downloadFile',
            file_references=[{'FileReference': file_reference}],
            compression=True)

    def get_file_list(self, *,
                      status=None,
                      file_type=None,
                      start_date=None,
                      end_date=None):
        """Get list of files

        Args:
            status (NEW|DLD|ALL): Filter new or downloaded files. If omitted,
                default value is all files, Code = “ALL”
            start_date (Date): Filter by date (inclusive). If start_date is not
                present, but EndDate is given, it means the filtering criteria
                    does not have a starting point.
            end_date (Date): Filter by date (inclusive). If end_date is not
                present, but StartDate is given, it means the filtering
                criteria does not have an ending point.
        """

        return self.__make_request(
            'downloadFileList',
            start_date=start_date,
            end_date=end_date,
            status=status,
            file_type=file_type,
            compression=False)
