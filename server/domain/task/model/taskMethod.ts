import type { TaskCreateVal, TaskEntity, TaskUpdateVal } from 'api/@types/task';
import type { UserEntity } from 'api/@types/user';
import assert from 'assert';
import { randomUUID } from 'crypto';
import { deletableTaskIdParser, taskIdParser } from 'service/idParsers';
import type { TaskDeleteVal } from './taskEntity';

export const taskMethod = {
  create: async (user: UserEntity, val: TaskCreateVal): Promise<TaskEntity> => {
    return {
      id: taskIdParser.parse(randomUUID()),
      done: false,
      label: val.label,
      createdTime: Date.now(),
      author: { id: user.id, displayName: user.displayName },
    };
  },
  update: (user: UserEntity, task: TaskEntity, val: TaskUpdateVal): TaskEntity => {
    assert(user.id === task.author.id);

    return { ...task, ...val };
  },
  delete: (user: UserEntity, task: TaskEntity): TaskDeleteVal => {
    assert(user.id === task.author.id);

    return { task, deletableId: deletableTaskIdParser.parse(task.id) };
  },
};
