#define DO_NOT_OPTIMIZE(var) asm volatile("" : "+r,m"(var) : : "memory")

int bar(int v) {
	return v;
}

int foo(int v) {
	return v % 2 ? bar(v + 1) : bar((v << 1) + 1);
}

int main() {
	for (int j = 0; j < 1000; j++)
		for (long long i = 0; i < 1000000000; i++) {
			int tem = 0;
			tem = foo(i);
			DO_NOT_OPTIMIZE(tem);
		}
	return 0;
}