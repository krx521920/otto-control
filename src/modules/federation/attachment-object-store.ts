export interface FederationAttachmentObject {
  objectKey: string;
  sizeBytes: number;
  checksumSha256: string;
}

export interface FederationAttachmentObjectStore {
  objectKey(attachmentId: string): string;
  createUpload(input: {
    objectKey: string;
    sha256: string;
    sizeBytes: number;
    expiresAt: Date;
  }): Promise<{
    method: 'PUT';
    url: string;
    headers: Record<string, string>;
    expiresAt: string;
  }>;
  inspect(objectKey: string): Promise<FederationAttachmentObject>;
  createDownload(input: {
    objectKey: string;
    expiresAt: Date;
  }): Promise<{ method: 'GET'; url: string; headers: Record<string, string>; expiresAt: string }>;
  remove(objectKey: string): Promise<void>;
}
