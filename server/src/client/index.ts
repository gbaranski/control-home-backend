import WebSocket from 'ws';
import { logSocketError, logError } from '@/cli';
import { convertToFirebaseUser, DocumentReference } from '@/services/firebase';
import { Device as DeviceType, Client, AnyDeviceData } from '@gbaranski/types';
import Device, { AnyDeviceObject } from '@/devices';

export default class WebSocketClient {
  private static _currentClients: WebSocketClient[] = [];

  public static get currentClients(): WebSocketClient[] {
    return this._currentClients;
  }

  public static addNewClient(client: WebSocketClient): void {
    this._currentClients.push(client);
  }

  public static removeClient(client: WebSocketClient): void {
    this._currentClients = this._currentClients.filter(
      (_client: WebSocketClient) => _client !== client,
    );
  }
  private static isDeviceCurrentlyConnected(deviceUid: string): boolean {
    return Device.currentDevices.some(
      activeDevice => deviceUid === activeDevice.deviceUid,
    );
  }

  private status = false;

  public userPermission: number | undefined;

  private fullAcccessDevices: DeviceType.FirebaseDevice[] = [];

  constructor(private websocket: WebSocket, public readonly clientUid: string) {
    this.setWebsocketHandling();
    this.setAccessDevices()
      .then(() => {
        this.interval();
        setInterval(() => this.interval(), 1000);
      })
      .catch(e => console.error(e));
  }

  async setAccessDevices(): Promise<void> {
    const firebaseUser = await convertToFirebaseUser(this.clientUid);
    this.userPermission = firebaseUser.permission;

    this.fullAcccessDevices = await Promise.all(
      firebaseUser.devices.full_access.map(
        async (doc: DocumentReference): Promise<DeviceType.FirebaseDevice> => {
          const deviceSnapshot = await doc.get();
          const deviceData = deviceSnapshot.data() as Partial<
            DeviceType.FirebaseDevice
          >;

          if (!deviceData.type) throw new Error('Type does not exist!');

          return {
            type: deviceData.type,
            uid: deviceSnapshot.id,
          };
        },
      ),
    );
  }

  private setWebsocketHandling() {
    this.websocket.on('message', message => this.handleMessage(message));
    this.websocket.on('error', err => {
      logError(err.message);
    });
    this.websocket.on('close', (code, reason) => {
      logError(`CODE: ${code} \nREASON:${reason}`);
      this.terminateConnection('Connection closed');
    });
  }

  private getCurrentConnectionWithAccess(): AnyDeviceObject[] {
    return Device.currentDevices.filter(device =>
      this.fullAcccessDevices.some(
        firebaseDevice => firebaseDevice.uid === device.deviceUid,
      ),
    );
  }

  private async interval(): Promise<void> {
    const deviceData: DeviceType.ActiveDevice<
      AnyDeviceData
    >[] = this.getCurrentConnectionWithAccess().map(
      (deviceObject): DeviceType.ActiveDevice<AnyDeviceData> => ({
        type: deviceObject.deviceType,
        uid: deviceObject.deviceUid,
        data: deviceObject.deviceData,
        status: deviceObject.status,
      }),
    );
    const clientResponse: Client.Response = {
      requestType: 'DATA',
      data: deviceData,
    };
    this.websocket.send(JSON.stringify(clientResponse));
  }

  private async sendDevices(): Promise<void> {
    const clientRes: Client.Response = {
      requestType: 'DEVICES',
      data: this.fullAcccessDevices,
    };
    this.websocket.send(JSON.stringify(clientRes));
  }

  private static parseMessage(message: WebSocket.Data): Client.Request {
    const parsedMsg = (message as unknown) as Client.Request;
    if (!parsedMsg.deviceUid) throw new Error('Uid is missing');
    if (!parsedMsg.requestType) throw new Error('Request type is missing');
    return parsedMsg;
  }

  private async handleMessage(message: WebSocket.Data): Promise<void> {
    try {
      if (
        message instanceof Buffer ||
        message instanceof Array ||
        message instanceof ArrayBuffer
      )
        throw new Error('Wrong message type');
      const parsedMsg = WebSocketClient.parseMessage(JSON.parse(message));
      const deviceObject = this.getCurrentConnectionWithAccess().find(
        _deviceObject => _deviceObject.deviceUid === parsedMsg.deviceUid,
      );
      if (!deviceObject) throw new Error('Could not find device');
      deviceObject.requestDevice(parsedMsg.requestType);
    } catch (e) {
      console.error(e.message);
    }
  }

  public terminateConnection(reason: string): void {
    this.websocket.terminate();
    logSocketError('Unknown', this.clientUid, reason, 'client');
    WebSocketClient.removeClient(this);
  }

  // private getDevicesStatus(): DeviceStatus[] {
  //   const deviceStatus: DeviceStatus[] = [];
  //   this.fullAccessCurrentDevices.forEach(currentDevice => {
  //     const _deviceStatus: DeviceStatus = {
  //       deviceUid: currentDevice.uid,
  //       status: WebSocketClient.isDeviceCurrentlyConnected(currentDevice.uid),
  //     };
  //     deviceStatus.push(_deviceStatus);
  //   });
  //   return deviceStatus;
  // }
}
