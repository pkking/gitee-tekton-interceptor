// cmd/main.go

package main

import (
	"log"

	"github.com/tektoncd/triggers/pkg/interceptors"
	"github.com/tektoncd/triggers/pkg/interceptors/server"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	// 导入我们自己实现的 gitee interceptor 包
	"github.com/pkking/gitee-tekton-interceptor/pkg/interceptors/gitee"
)

func main() {
	// 创建 Kubernetes in-cluster 配置
	config, err := rest.InClusterConfig()
	if err != nil {
		log.Fatalf("Failed to get in-cluster config: %v", err)
	}

	// 创建 Kubernetes clientset
	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Failed to create k8s client: %v", err)
	}

	// 创建 Gitee Interceptor 实例，并传入 k8s client
	giteeInterceptor := gitee.New(kubeClient)

	// 注册所有你想在这个服务中暴露的拦截器
	interceptors := map[string]interceptors.InterceptorInterface{
		"gitee": giteeInterceptor,
	}

	// 启动拦截器服务
	s, err := server.NewFromPort("8080", interceptors)
	if err != nil {
		log.Fatalf("failed to create interceptor server: %v", err)
	}

	log.Println("Custom interceptor server listening on port 8080, with Gitee interceptor registered")
	if err := s.ListenAndServe(); err != nil {
		log.Fatalf("failed to listen and serve: %v", err)
	}
}
