// Copyright 2026 RustFS Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Two operations in one group, which is how a family of operations in one file registers. A second
// file with `group = buckets` generates `register_buckets`, and the assembly point calls both.

#[handlers(group = objects)]
impl Fs {
    async fn put_object(&self, request: Req<PutObject>) -> HandlerResult<PutObject> {
        self.write(request.into_input()).await
    }

    async fn list_objects_v2(&self, request: Req<ListObjectsV2>) -> HandlerResult<ListObjectsV2> {
        self.list(request.into_input()).await
    }
}
