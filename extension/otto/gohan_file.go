package otto

import (
	"fmt"
	"github.com/dop251/otto"
	"io/ioutil"
	"os"
	"os/exec"
)

func init() {
	gohanFileInit := func(env *Environment) {
		vm := env.VM
		builtins := map[string]interface{}{
			"gohan_file_list": func(call otto.FunctionCall) otto.Value {
				VerifyCallArguments(&call, "gohan_file_list", 1)
				dirName := call.Argument(0).String()

				cmd := "ls"
				cmdArgs := []string{dirName}
				cmdOut, err := exec.Command(cmd, cmdArgs...).Output()
				if err != nil {
					ThrowOttoException(&call, fmt.Sprintf("Error in listing files: %v", err))
				}

				value, _ := vm.ToValue(string(cmdOut))
				return value
			},
			"gohan_file_dir": func(call otto.FunctionCall) otto.Value {
				VerifyCallArguments(&call, "gohan_file_dir", 1)
				fileName := call.Argument(0).String()
				file, err := os.Open(fileName)
				if err != nil {
					ThrowOttoException(&call, fmt.Sprintf("%v", err))
				}
				stat, err := file.Stat()
				if err != nil {
					ThrowOttoException(&call, fmt.Sprintf("%v", err))
				}
				value, _ := vm.ToValue(stat.IsDir())
				return value
			},

			"gohan_file_read": func(call otto.FunctionCall) otto.Value {
				VerifyCallArguments(&call, "gohan_file_read", 1)
				fileName := call.Argument(0).String()
				bytes, err := ioutil.ReadFile(fileName)
				if err != nil {
					ThrowOttoException(&call, fmt.Sprintf("%v", err))
				}
				value, _ := vm.ToValue(string(bytes))
				return value
			},
		}
		for name, object := range builtins {
			vm.Set(name, object)
		}
	}
	RegisterInit(gohanFileInit)
}
