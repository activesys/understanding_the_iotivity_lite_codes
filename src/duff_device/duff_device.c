#include <stdio.h>
#include <stdlib.h>

int func(void)
{
    static int i, s = 0;
    switch (s) {
    case 0:
        printf("The function performs initialization only once.\n");
        for (i = 0; i < 10; ++i) {
            s = 1;
            printf("so we will come back to \"case 1\".\n");
            return i;
    case 1:
        printf("resume control straight after the return.\n");
        }
    }
}

int main()
{
    printf("The func returns %d\n", func());
    printf("The func returns %d\n", func());
    printf("The func returns %d\n", func());
    printf("The func returns %d\n", func());
    return 0;
}
