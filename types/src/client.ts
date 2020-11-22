import { GeoPoint, ReadWriteExecuteAccess } from '.';
import { Device } from './device';

export namespace Client {
  export type UserRole = 'admin' | 'user';

  export interface DeviceRequestUser {
    token: string;
    geoPoint: GeoPoint;
  }

  export interface DeviceRequestByActionName {
    user: DeviceRequestUser;
    device: {
      action: Device.Action;
      data?: string;
    };
  }

  export interface DeviceRequestByUID {
    user: DeviceRequestUser;
    device: {
      uid: string;
      action: number;
      data?: string;
    };
  }

  export interface FirebaseUserDevice extends ReadWriteExecuteAccess {
    uid: string;
  }

  export interface FirebaseUser {
    devices: FirebaseUserDevice[];
    role: UserRole;
    uid: string;
    username: string;
  }
}
