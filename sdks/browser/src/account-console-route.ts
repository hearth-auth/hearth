import type {
  AccountSession,
  ChangePasswordRequest,
  DataExportJob,
  HearthClient,
  MfaDevice,
  UpdateUserProfileRequest,
  UserProfile,
} from "./client.js";

type AccountConsoleClient = Pick<
  HearthClient,
  | "getProfile"
  | "updateProfile"
  | "changePassword"
  | "listSessions"
  | "revokeSession"
  | "revokeOtherSessions"
  | "listMfaDevices"
  | "removeMfaDevice"
  | "createDataExport"
  | "getDataExport"
  | "downloadDataExport"
>;

export interface AccountConsoleRouteLoadInput {
  dataExportId?: string;
}

export interface AccountConsoleRouteData {
  profile: UserProfile;
  sessions: AccountSession[];
  mfaDevices: MfaDevice[];
  dataExport: DataExportJob | null;
}

export interface AccountConsoleRoute {
  load: (input?: AccountConsoleRouteLoadInput) => Promise<AccountConsoleRouteData>;
  actions: {
    updateProfile: (payload: UpdateUserProfileRequest) => Promise<UserProfile>;
    changePassword: (payload: ChangePasswordRequest) => Promise<void>;
    revokeSession: (sessionId: string) => Promise<void>;
    revokeOtherSessions: () => Promise<void>;
    removeMfaDevice: (deviceId: string) => Promise<void>;
    createDataExport: () => Promise<DataExportJob>;
    getDataExport: (exportId: string) => Promise<DataExportJob>;
    downloadDataExport: (exportId: string) => Promise<Blob>;
  };
}

/**
 * Creates a route-ready account-console controller.
 * Use `load()` in your route loader and `actions.*` in form/button handlers.
 */
export function createAccountConsoleRoute(client: AccountConsoleClient): AccountConsoleRoute {
  return {
    async load(input = {}) {
      const [profile, sessions, mfaDevices, dataExport] = await Promise.all([
        client.getProfile(),
        client.listSessions(),
        client.listMfaDevices(),
        input.dataExportId ? client.getDataExport(input.dataExportId) : Promise.resolve(null),
      ]);

      return {
        profile,
        sessions,
        mfaDevices,
        dataExport,
      };
    },
    actions: {
      updateProfile: (payload) => client.updateProfile(payload),
      changePassword: (payload) => client.changePassword(payload),
      revokeSession: (sessionId) => client.revokeSession(sessionId),
      revokeOtherSessions: () => client.revokeOtherSessions(),
      removeMfaDevice: (deviceId) => client.removeMfaDevice(deviceId),
      createDataExport: () => client.createDataExport(),
      getDataExport: (exportId) => client.getDataExport(exportId),
      downloadDataExport: (exportId) => client.downloadDataExport(exportId),
    },
  };
}
