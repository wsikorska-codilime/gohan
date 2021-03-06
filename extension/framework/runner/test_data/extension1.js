// Copyright (C) 2015 NTT Innovation Institute, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.


function from_extension1() {
}

gohan_register_handler("post_list", function(context) {
  context.triggered = true;
});

function CustomError(message) {
  this.message = message;
}
CustomError.prototype = new Error;

gohan_register_handler("pre_list", function(context) {
  throw new CustomError("ExtensionError");
});

gohan_register_handler("custom_action", function (context) {
  var tx = gohan_db_transaction();
  var new_network = {
    "id": context.id,
    "name": "Net1",
    "status": "ACTIVE"
  };
  gohan_db_create(tx, "network", new_network);
  tx.Commit();
  tx.Close();

  tx = gohan_db_transaction();
  var new_network = {
    "id": context.id,
    "status": "DOWN"
  };
  gohan_db_update(tx, "network", new_network);
  tx.Commit();
  tx.Close();
});
