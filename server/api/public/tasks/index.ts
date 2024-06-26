import type { MaybeId } from 'api/@types/brandedId';
import type { TaskCreateVal, TaskEntity, TaskUpdateVal } from 'api/@types/task';
import type { DefineMethods } from 'aspida';

export type Methods = DefineMethods<{
  get: {
    resBody: TaskEntity[];
    query?: {
      limit?: number;
    };
  };

  post: {
    reqBody: TaskCreateVal;
    resBody: TaskEntity;
  };

  patch: {
    reqBody: TaskUpdateVal;
    status: 204;
    resBody: TaskEntity;
  };

  delete: {
    reqBody: {
      taskId: MaybeId['task'];
    };
    status: 204;
    resBody: TaskEntity;
  };
}>;
