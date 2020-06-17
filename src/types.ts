export enum AlarmRequestType {
  GET_DATA = '/getESPData',
  SET_TIME = '/setAlarm',
  SWITCH_STATE = '/setAlarmState',
  TEST_ALARM = '/testAlarm',
}
export enum WaterRequestType {
  GET_DATA = '/getESPData',
  START_MIXING = '/startMixing',
}

export interface AlarmclockData {
  currentTime: string;
  alarmTime: string;
  remainingTime: string;
  alarmState: number;
  temperature: number;
  humidity: number;
  heatIndex: number;
}

export interface WatermixerData {
  remainingSeconds: string;
  isTimerOn: string;
}
