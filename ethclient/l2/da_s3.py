"""S3-backed DA (Data Availability) provider."""

from __future__ import annotations

from typing import Optional

from ethclient.common.crypto import keccak256
from ethclient.l2.interfaces import DAProvider


class S3DAProvider(DAProvider):
    """Store batch data in an S3 bucket.

    Requires ``boto3`` (install via ``pip install py-ethclient[s3]``).
    Commitments are keccak256(batch_number_8bytes || data).
    """

    def __init__(
        self,
        bucket: str,
        prefix: str = "batches/",
        region: Optional[str] = None,
        endpoint_url: Optional[str] = None,
    ) -> None:
        try:
            import boto3  # type: ignore[import-untyped]
        except ImportError:
            raise ImportError(
                "boto3 is required for S3DAProvider. "
                "Install it with: pip install py-ethclient[s3]"
            )
        kwargs: dict = {}
        if region:
            kwargs["region_name"] = region
        if endpoint_url:
            kwargs["endpoint_url"] = endpoint_url
        self._client = boto3.client("s3", **kwargs)
        self._bucket = bucket
        self._prefix = prefix

    def _key(self, batch_number: int) -> str:
        return f"{self._prefix}{batch_number:08d}"

    def store_batch(self, batch_number: int, data: bytes) -> bytes:
        commitment = keccak256(batch_number.to_bytes(8, "big") + data)
        self._client.put_object(
            Bucket=self._bucket,
            Key=self._key(batch_number),
            Body=data,
        )
        return commitment

    def retrieve_batch(self, batch_number: int, *, expected_commitment: bytes = None) -> Optional[bytes]:
        try:
            resp = self._client.get_object(
                Bucket=self._bucket,
                Key=self._key(batch_number),
            )
            data = resp["Body"].read()
        except Exception:
            return None
        if data is not None and expected_commitment is not None:
            import logging
            actual = keccak256(batch_number.to_bytes(8, "big") + data)
            if actual != expected_commitment:
                logging.getLogger(__name__).warning(
                    "DA commitment mismatch for batch #%d", batch_number
                )
                return None
        return data

    def verify_commitment(self, batch_number: int, commitment: bytes) -> bool:
        data = self.retrieve_batch(batch_number)
        if data is None:
            return False
        expected = keccak256(batch_number.to_bytes(8, "big") + data)
        return expected == commitment
