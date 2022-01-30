#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <math.h>
#include <stdlib.h>
long long tentotwo(long long a)//8位十进制转二进制
{
	long long  b, c;
	c = 0;
	int i = 0;
	while (a != 0)
	{
		b = a % 2;
		c = c + b * (long long)pow(10, i);
		i++;
		a = a / 2;
	}
	return c;
}
void longtentotwo(long long a, int data[])//数据集十进制转二进制
{
	long long  b, c;
	c = 0;
	int i = 0;
	while (a != 0)
	{
		b = a % 2;
		c = c + b * (long long)pow(10, i % 8);
		i++;
		a = a / 2;
		if (i % 8 == 0)//以八个为一组分开
		{
			data[4 - (i / 8)] = c;
			c = 0;
		}
	}
	if (i < 8)
	{
		data[3] = c;
	}
	else if (i > 8 && i < 16)
		data[2] = c;
	else if (i > 16 && i < 24)
		data[1] = c;
	else if (i > 24 && i < 32)
		data[0] = c;
}
long long buyi(int wei)//每位都是1
{
	long long s = 0;
	for (int i = 0; i < wei; i++)
	{
		s += (long long)pow(10, i);
	}
	return s;
}
void totwo_min(int arr[], int brr[])
{
	long long wlh = 0;//网络号
	if (arr[4] < 32)
	{
		switch (arr[4] / 8)
		{
		case 0:
		{
			wlh = tentotwo(arr[0]) / (long long)pow(10, 8 - arr[4] % 8);
			brr[0] = wlh * (long long)pow(10, 8 - arr[4] % 8);
			brr[1] = 0;
			brr[2] = 0;
			brr[3] = 0;
			break;
		}
		case 1:
		{
			wlh = tentotwo(arr[1]) / (long long)pow(10, 8 - arr[4] % 8);
			brr[0] = tentotwo(arr[0]);
			brr[1] = wlh * (long long)pow(10, 8 - arr[4] % 8);
			brr[2] = 0;
			brr[3] = 0;
			break;
		}
		case 2:
		{
			wlh = tentotwo(arr[2]) / (long long)pow(10, 8 - arr[4] % 8);
			brr[0] = tentotwo(arr[0]);
			brr[1] = tentotwo(arr[1]);
			brr[2] = pow(10, 8 - arr[4] % 8) * wlh;
			brr[3] = 0;
			break;
		}
		case 3:
		{
			wlh = tentotwo(arr[3]) / (long long)(8 - pow(10, arr[4] % 8));
			brr[0] = tentotwo(arr[0]);
			brr[1] = tentotwo(arr[1]);
			brr[2] = tentotwo(arr[2]);
			brr[3] = pow(10, 8 - arr[4] % 8) * wlh;
			break;
		}
		}
	}
	else
	{
		brr[0] = tentotwo(arr[0]);
		brr[1] = tentotwo(arr[1]);
		brr[2] = tentotwo(arr[2]);
		brr[3] = tentotwo(arr[3]);
	}
}
void totwo_max(int arr[], int barr[])
{
	long long wlh = 0;//网络号
	if (arr[4] < 32)
	{
		switch (arr[4] / 8)
		{
		case 0:
		{
			wlh = tentotwo(arr[0]) / (long long)pow(10, 8 - arr[4] % 8);
			barr[0] = wlh * (long long)pow(10, 8 - arr[4] % 8) + buyi(8 - arr[4] % 8);
			barr[1] = 11111111;
			barr[2] = 11111111;
			barr[3] = 11111111;
			break;
		}
		case 1:
		{
			wlh = tentotwo(arr[1]) / (long long)pow(10, 8 - arr[4] % 8);
			barr[0] = tentotwo(arr[0]);
			barr[1] = wlh * (long long)pow(10, 8 - arr[4] % 8) + buyi(8 - arr[4] % 8);
			barr[2] = 11111111;
			barr[3] = 11111111;
			break;
		}
		case 2:
		{
			wlh = tentotwo(arr[2]) / (long long)pow(10, 8 - arr[4] % 8);
			barr[0] = tentotwo(arr[0]);
			barr[1] = tentotwo(arr[1]);
			barr[2] = pow(10, 8 - arr[4] % 8) * wlh + buyi(8 - arr[4] % 8);
			barr[3] = 11111111;
			break;
		}
		case 3:
		{
			wlh = tentotwo(arr[3]) / (long long)(8 - pow(10, arr[4] % 8));
			barr[0] = tentotwo(arr[0]);
			barr[1] = tentotwo(arr[1]);
			barr[2] = tentotwo(arr[2]);
			barr[3] = pow(10, 8 - arr[4] % 8) * wlh + buyi(8 - arr[4] % 8);
			break;
		}
		}
	}
	else
	{
		barr[0] = tentotwo(arr[0]);
		barr[1] = tentotwo(arr[1]);
		barr[2] = tentotwo(arr[2]);
		barr[3] = tentotwo(arr[3]);
	}
}
typedef struct
{
	long long from_ip_;//源IP地址
	long long to_ip_;//目的IP地址
}PREDATA;//数据集转换进制前结构体
typedef struct
{
	int from_ip[4]; //源IP地址二进制
	int to_ip[4];//目的IP地址二进制
	int from_duan;//源端口
	int to_duan;//目的端口
	int xieyi;//传输层协议
}DATA;//数据集转换进制后结构体
typedef struct
{
	int from_rule_ip[5];
	int to_rule_ip[5];
}PRERULE; //规则集转换进制前结构体
typedef struct
{
	int from_ip_min[4];
	int from_ip_max[4];
	int to_ip_min[4];
	int to_ip_max[4];

	int from_duan_min;
	int from_duan_max;
	int to_duan_min;
	int to_duan_max;
	int xieyi_min;
	int xieyi_max;
}RULE;//规则集转换进制后结构体
int comp(int min, int max, int data)
{
	if (min < data && data < max)
		return 1;
	else if (min == data && data < max)
		return 2;
	else if (min < data && data == max)
		return 3;
	else if (min == data && data == max)
		return 4;
	else
		return 0;
}
int compsz(int a[], int b[], int c[])
{
	if (comp(a[0], b[0], c[0]) == 1)//严格
	{
		return 1;
	}
	else if (comp(a[0], b[0], c[0]) == 2)
	{
		if (a[1] < c[1])
			return 1;
		else if (a[1] == c[1])
		{
			if (a[2] < c[2])
				return 1;
			else if (a[2] == c[2])
			{
				if (a[3] <= c[3])
					return 1;
			}
		}
	}
	else if (comp(a[0], b[0], c[0]) == 3)
	{
		if (c[1] < b[1])
			return 1;
		else if (b[1] == c[1])
		{
			if (c[2] < b[2])
				return 1;
			else if (b[2] == c[2])
			{
				if (c[3] <= b[3])
					return 1;
			}
		}
	}
	else if (comp(a[0], b[0], c[0]) == 4)
	{
		if (comp(a[1], b[1], c[1]) == 1)
			return 1;
		else if (comp(a[1], b[1], c[1]) == 2)
		{
			if (a[2] < c[2])
				return 1;
			else if (a[2] == c[2])
			{
				if (a[3] <= c[3])
					return 1;
			}
		}
		else if (comp(a[1], b[1], c[1]) == 3)
		{
			if (c[2] < b[2])
				return 1;
			else if (b[2] == c[2])
			{
				if (c[3] <= b[3])
					return 1;
			}
		}
		else if (comp(a[1], b[1], c[1]) == 4)
		{
			if (comp(a[2], b[2], c[2]) == 1)
				return 1;
			else if (comp(a[2], b[2], c[2]) == 2)
			{
				if (a[3] <= c[3])
					return 1;
			}
			else if (comp(a[2], b[2], c[2]) == 3)
			{
				if (c[3] <= b[3])
					return 1;
			}
			else if (comp(a[2], b[2], c[2]) == 4)
			{
				if (a[3] <= c[3] && c[3] <= b[3])
					return 1;
			}
		}
	}
	return 0;
}
int main()
{
	PRERULE prerule = { 0 };
	RULE rule[1000] = { 0 };
	//规则集指针
	char ruleinput[20] = { 0 };
	char datainput[20] = {0};
	printf("请输入：./main <规则集文件名> <数据集文件名>");
	printf("（例如：./main rule1.txt packet1.txt）\n");
	scanf("./main %s %s", ruleinput,datainput);
	FILE* rulefp = fopen(ruleinput, "r");
	if (rulefp == NULL)//测试文件是否打开
		printf("文件没打开");
	else
	{
		printf("文件打开了");
		fseek(rulefp, 0, SEEK_SET);
		int i = 0;
		char ch = '1';
		for (i = 1; ch != EOF; i++)
		{
			//源ip范围
			fscanf_s(rulefp, "@%d.%d.%d.%d/%d", &(prerule.from_rule_ip[0]), &(prerule.from_rule_ip[1]), &(prerule.from_rule_ip[2]), &(prerule.from_rule_ip[3]), &(prerule.from_rule_ip[4]));
			totwo_min(prerule.from_rule_ip, rule[i].from_ip_min);
			totwo_max(prerule.from_rule_ip, rule[i].from_ip_max);

			//目的ip范围
			fscanf_s(rulefp, "%d.%d.%d.%d/%d", &(prerule.to_rule_ip[0]), &(prerule.to_rule_ip[1]), &(prerule.to_rule_ip[2]), &(prerule.to_rule_ip[3]), &(prerule.to_rule_ip[4]));
			totwo_min(prerule.to_rule_ip, rule[i].to_ip_min);
			totwo_max(prerule.to_rule_ip, rule[i].to_ip_max);

			//源、目端口范围
			fscanf_s(rulefp, "%d : %d", &(rule[i].from_duan_min), &(rule[i].from_duan_max));
			fscanf_s(rulefp, "%d : %d", &(rule[i].to_duan_min), &(rule[i].to_duan_max));

			//协议范围
			int xieyi1 = 0;
			int  xieyi2 = 0;
			fscanf_s(rulefp, "%i/%i", &xieyi1, &xieyi2);
			if (xieyi2 == 255)
			{
				rule[i].xieyi_max = xieyi1;
				rule[i].xieyi_min = xieyi1;
			}
			else if (xieyi2 == 0)
			{
				rule[i].xieyi_max = 255;
				rule[i].xieyi_min = 0;
			}
			ch = fgetc(rulefp);
		}
		int end = i - 1;
		fclose(rulefp);//关闭规则集

		FILE* datafp;//第一个数据集指针
		datafp = fopen(datainput, "r");
		FILE* resfp;
		resfp = fopen("res.txt", "w");

		PREDATA predata = { 0 };
		DATA data = { 0 };
		fseek(datafp, 0, SEEK_SET);
		fseek(resfp, 0, SEEK_SET);
		int j = 0;
		ch = 'ch';
		for (j = 1; ch != EOF; j++)//数据集
		{
			//每次循环扫描一行数据
			fscanf_s(datafp, "%lld %lld %d %d %d", &(predata.from_ip_), &(predata.to_ip_), &(data.from_duan), &(data.to_duan), &(data.xieyi));
			longtentotwo(predata.from_ip_, data.from_ip);
			longtentotwo(predata.to_ip_, data.to_ip);
			for (i = 1; i <= end; i++)//规则集
			{
				if (compsz(rule[i].from_ip_min, rule[i].from_ip_max, data.from_ip) == 1 &&
					compsz(rule[i].to_ip_min, rule[i].to_ip_max, data.to_ip) == 1 &&
					comp(rule[i].from_duan_min, rule[i].from_duan_max, data.from_duan) != 0 &&
					comp(rule[i].to_duan_min, rule[i].to_duan_max, data.to_duan) != 0 &&
					comp(rule[i].xieyi_min, rule[i].xieyi_max, data.xieyi) != 0)
				{
					fprintf(resfp, "%d : %d\n", j, i - 1);
					break;
				}
			}
			if (i > end)
			{
				fprintf(resfp, "%d : -1", j);
			}
			ch = fgetc(datafp);
		}
		//关闭文件
		fclose(datafp);
		fclose(resfp);
	}
	return 0;
}