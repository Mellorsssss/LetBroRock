#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <thread>
#include <time.h>
#include <unistd.h>
using namespace std;

#define MAX_TASKS     10
#define TASK_NAME_LEN 20

typedef struct {
	char name[TASK_NAME_LEN];
	int priority;
	int completed;
} Task;

void add_task(Task *tasks, int *task_count, const char *name, int priority) {
	if (*task_count >= MAX_TASKS) {
		printf("Task list is full.\n");
		return;
	}
	Task *new_task = &tasks[*task_count];
	strncpy(new_task->name, name, TASK_NAME_LEN - 1);
	new_task->name[TASK_NAME_LEN - 1] = '\0';
	new_task->priority = priority;
	new_task->completed = 0;
	(*task_count)++;
}

void complete_task(Task *tasks, int task_count, const char *name) {
	for (int i = 0; i < task_count; i++) {
		if (strcmp(tasks[i].name, name) == 0) {
			tasks[i].completed = 1;
			printf("Task '%s' completed.\n", name);
			return;
		}
	}
	printf("Task '%s' not found.\n", name);
}

void list_tasks(Task *tasks, int task_count) {
	for (int i = 0; i < task_count; i++) {
		printf("Task: %s, Priority: %d, Completed: %s\n", tasks[i].name, tasks[i].priority,
		       tasks[i].completed ? "Yes" : "No");
	}
}

void generate_random_task(Task *tasks, int *task_count) {
	static const char *task_names[] = {"Task1", "Task2", "Task3", "Task4", "Task5"};
	const char *name = task_names[rand() % 5];
	int priority = rand() % 10 + 1;
	add_task(tasks, task_count, name, priority);
}

int work() {
	Task tasks[MAX_TASKS];
	int task_count = 0;
	srand(0);

	while (true) {
		int try_cnt = 5000000;
		while (try_cnt--) {
			int choice = rand() % 3;
			switch (choice) {
			case 0:
				generate_random_task(tasks, &task_count);
				break;
			case 1:
				if (task_count > 0) {
					int index = rand() % task_count;
					complete_task(tasks, task_count, tasks[index].name);
				}
				break;
			case 2:
				list_tasks(tasks, task_count);
				break;
			}
			// sleep(1); // Simulate some work
		}
	}
	return 0;
}

int main() {
	std::thread t(work);
	printf("in a new thread\n");
	if (t.joinable()) {
		t.join();
	}
	return 0;
}