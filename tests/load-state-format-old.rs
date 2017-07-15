/*
    Copyright © 2016 Zetok Zalbavar <zexavexxe@gmail.com>

    This file is part of Tox.

    Tox is libre software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Tox is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Tox.  If not, see <http://www.gnu.org/licenses/>.
*/

extern crate tox;

use tox::toxcore::binary_io::*;
use tox::toxcore::state_format::old::*;

#[test]
fn test_state_format_old_load() {
    let bytes = include_bytes!("state-format-old-data/profile-no-friends.tox");
    let profile = State::from_bytes(bytes).unwrap();
    let profile_b = profile.to_bytes();
    // c-toxcore appends `0`s after EOF because reasons
    assert_eq!(&bytes[..profile_b.len()], profile_b.as_slice());
    // TODO: rewrite this check with bare comparisons
    assert_eq!(&format!("{:?}", profile),
               "State { nospamkeys: NospamKeys { nospam: NoSpam([8, 121, 102, 250]), pk: PublicKey([190, 94, 7, 2, 219, 8, 181, 85, 72, 201, 209, 0, 113, 106, 161, 39, 4, 198, 174, 163, 126, 121, 251, 218, 126, 227, 69, 62, 220, 152, 0, 102]), sk: SecretKey(****) }, dhtstate: DhtState([PackedNode { ip_type: U4, saddr: V4(95.31.20.151:33445), pk: PublicKey([156, 166, 155, 183, 77, 231, 192, 86, 209, 204, 107, 22, 171, 138, 10, 56, 114, 92, 3, 73, 209, 135, 216, 153, 103, 102, 149, 133, 132, 211, 147, 64]) }, PackedNode { ip_type: U4, saddr: V4(51.254.84.212:33445), pk: PublicKey([174, 194, 4, 185, 164, 80, 20, 18, 213, 240, 187, 103, 217, 200, 27, 93, 179, 238, 106, 218, 100, 18, 45, 50, 163, 233, 176, 147, 213, 68, 50, 125]) }, PackedNode { ip_type: U4, saddr: V4(85.143.219.211:33445), pk: PublicKey([175, 184, 58, 100, 7, 45, 218, 251, 162, 141, 244, 154, 111, 40, 128, 29, 83, 188, 220, 162, 231, 183, 95, 193, 86, 96, 155, 78, 134, 177, 138, 26]) }, PackedNode { ip_type: U4, saddr: V4(96.35.0.163:33445), pk: PublicKey([173, 37, 20, 232, 142, 175, 234, 107, 45, 211, 242, 58, 72, 24, 35, 230, 241, 7, 156, 20, 158, 56, 100, 145, 248, 208, 243, 52, 216, 165, 243, 114]) }, PackedNode { ip_type: U4, saddr: V4(82.154.147.70:10000), pk: PublicKey([172, 61, 124, 160, 207, 20, 206, 199, 203, 34, 27, 144, 196, 172, 176, 78, 226, 127, 139, 19, 64, 183, 235, 143, 233, 26, 219, 65, 235, 44, 77, 112]) }, PackedNode { ip_type: U4, saddr: V4(95.215.44.78:33445), pk: PublicKey([103, 45, 190, 39, 180, 173, 185, 213, 251, 16, 90, 107, 182, 72, 178, 248, 253, 184, 155, 51, 35, 72, 106, 122, 33, 150, 131, 22, 224, 18, 2, 60]) }, PackedNode { ip_type: U4, saddr: V4(163.172.137.179:33445), pk: PublicKey([102, 52, 179, 127, 247, 211, 214, 237, 83, 12, 183, 48, 249, 21, 149, 131, 204, 210, 229, 104, 163, 146, 18, 255, 176, 190, 47, 245, 129, 215, 134, 69]) }, PackedNode { ip_type: U4, saddr: V4(130.133.110.14:33445), pk: PublicKey([70, 31, 163, 119, 110, 240, 250, 101, 95, 26, 5, 71, 125, 241, 179, 182, 20, 247, 214, 177, 36, 247, 219, 29, 212, 254, 60, 8, 176, 59, 100, 15]) }, PackedNode { ip_type: U4, saddr: V4(185.117.155.45:33445), pk: PublicKey([67, 72, 100, 148, 200, 205, 250, 43, 234, 92, 231, 144, 1, 161, 255, 81, 20, 116, 231, 226, 74, 149, 21, 133, 80, 4, 75, 191, 47, 8, 112, 80]) }, PackedNode { ip_type: U4, saddr: V4(46.163.140.6:33445), pk: PublicKey([68, 191, 46, 13, 148, 55, 90, 44, 236, 217, 123, 149, 194, 0, 27, 93, 230, 147, 215, 0, 134, 234, 85, 239, 62, 167, 93, 77, 231, 51, 42, 61]) }, PackedNode { ip_type: U4, saddr: V4(91.121.66.124:33445), pk: PublicKey([78, 63, 125, 55, 41, 86, 100, 187, 208, 116, 27, 109, 188, 182, 67, 29, 108, 215, 127, 196, 16, 83, 56, 194, 252, 49, 86, 123, 245, 200, 34, 74]) }, PackedNode { ip_type: U4, saddr: V4(82.154.147.70:10000), pk: PublicKey([172, 61, 124, 160, 207, 20, 206, 199, 203, 34, 27, 144, 196, 172, 176, 78, 226, 127, 139, 19, 64, 183, 235, 143, 233, 26, 219, 65, 235, 44, 77, 112]) }, PackedNode { ip_type: U4, saddr: V4(91.121.66.124:33445), pk: PublicKey([78, 63, 125, 55, 41, 86, 100, 187, 208, 116, 27, 109, 188, 182, 67, 29, 108, 215, 127, 196, 16, 83, 56, 194, 252, 49, 86, 123, 245, 200, 34, 74]) }, PackedNode { ip_type: U4, saddr: V4(95.215.44.78:33445), pk: PublicKey([103, 45, 190, 39, 180, 173, 185, 213, 251, 16, 90, 107, 182, 72, 178, 248, 253, 184, 155, 51, 35, 72, 106, 122, 33, 150, 131, 22, 224, 18, 2, 60]) }, PackedNode { ip_type: U4, saddr: V4(163.172.137.179:33445), pk: PublicKey([102, 52, 179, 127, 247, 211, 214, 237, 83, 12, 183, 48, 249, 21, 149, 131, 204, 210, 229, 104, 163, 146, 18, 255, 176, 190, 47, 245, 129, 215, 134, 69]) }, PackedNode { ip_type: U4, saddr: V4(95.31.20.151:33445), pk: PublicKey([156, 166, 155, 183, 77, 231, 192, 86, 209, 204, 107, 22, 171, 138, 10, 56, 114, 92, 3, 73, 209, 135, 216, 153, 103, 102, 149, 133, 132, 211, 147, 64]) }, PackedNode { ip_type: U4, saddr: V4(85.143.219.211:33445), pk: PublicKey([175, 184, 58, 100, 7, 45, 218, 251, 162, 141, 244, 154, 111, 40, 128, 29, 83, 188, 220, 162, 231, 183, 95, 193, 86, 96, 155, 78, 134, 177, 138, 26]) }, PackedNode { ip_type: U4, saddr: V4(51.254.84.212:33445), pk: PublicKey([174, 194, 4, 185, 164, 80, 20, 18, 213, 240, 187, 103, 217, 200, 27, 93, 179, 238, 106, 218, 100, 18, 45, 50, 163, 233, 176, 147, 213, 68, 50, 125]) }, PackedNode { ip_type: U4, saddr: V4(96.35.0.163:33445), pk: PublicKey([173, 37, 20, 232, 142, 175, 234, 107, 45, 211, 242, 58, 72, 24, 35, 230, 241, 7, 156, 20, 158, 56, 100, 145, 248, 208, 243, 52, 216, 165, 243, 114]) }, PackedNode { ip_type: U4, saddr: V4(82.154.147.70:10000), pk: PublicKey([172, 61, 124, 160, 207, 20, 206, 199, 203, 34, 27, 144, 196, 172, 176, 78, 226, 127, 139, 19, 64, 183, 235, 143, 233, 26, 219, 65, 235, 44, 77, 112]) }, PackedNode { ip_type: U4, saddr: V4(91.121.66.124:33445), pk: PublicKey([78, 63, 125, 55, 41, 86, 100, 187, 208, 116, 27, 109, 188, 182, 67, 29, 108, 215, 127, 196, 16, 83, 56, 194, 252, 49, 86, 123, 245, 200, 34, 74]) }, PackedNode { ip_type: U4, saddr: V4(163.172.137.179:33445), pk: PublicKey([102, 52, 179, 127, 247, 211, 214, 237, 83, 12, 183, 48, 249, 21, 149, 131, 204, 210, 229, 104, 163, 146, 18, 255, 176, 190, 47, 245, 129, 215, 134, 69]) }, PackedNode { ip_type: U4, saddr: V4(95.215.44.78:33445), pk: PublicKey([103, 45, 190, 39, 180, 173, 185, 213, 251, 16, 90, 107, 182, 72, 178, 248, 253, 184, 155, 51, 35, 72, 106, 122, 33, 150, 131, 22, 224, 18, 2, 60]) }, PackedNode { ip_type: U4, saddr: V4(95.31.20.151:33445), pk: PublicKey([156, 166, 155, 183, 77, 231, 192, 86, 209, 204, 107, 22, 171, 138, 10, 56, 114, 92, 3, 73, 209, 135, 216, 153, 103, 102, 149, 133, 132, 211, 147, 64]) }, PackedNode { ip_type: U4, saddr: V4(96.35.0.163:33445), pk: PublicKey([173, 37, 20, 232, 142, 175, 234, 107, 45, 211, 242, 58, 72, 24, 35, 230, 241, 7, 156, 20, 158, 56, 100, 145, 248, 208, 243, 52, 216, 165, 243, 114]) }, PackedNode { ip_type: U4, saddr: V4(51.254.84.212:33445), pk: PublicKey([174, 194, 4, 185, 164, 80, 20, 18, 213, 240, 187, 103, 217, 200, 27, 93, 179, 238, 106, 218, 100, 18, 45, 50, 163, 233, 176, 147, 213, 68, 50, 125]) }, PackedNode { ip_type: U4, saddr: V4(85.143.219.211:33445), pk: PublicKey([175, 184, 58, 100, 7, 45, 218, 251, 162, 141, 244, 154, 111, 40, 128, 29, 83, 188, 220, 162, 231, 183, 95, 193, 86, 96, 155, 78, 134, 177, 138, 26]) }]), friends: Friends([]), name: Name([116, 101, 115, 116, 95, 112, 117, 98, 108, 105, 99]), status_msg: StatusMsg([84, 111, 120, 117, 106, 196, 153, 32, 110, 97, 32, 113, 84, 111, 120]), status: Online, tcp_relays: TcpRelays([PackedNode { ip_type: T4, saddr: V4(95.215.44.78:33445), pk: PublicKey([103, 45, 190, 39, 180, 173, 185, 213, 251, 16, 90, 107, 182, 72, 178, 248, 253, 184, 155, 51, 35, 72, 106, 122, 33, 150, 131, 22, 224, 18, 2, 60]) }]), path_nodes: PathNodes([PackedNode { ip_type: U4, saddr: V4(82.154.147.70:10000), pk: PublicKey([172, 61, 124, 160, 207, 20, 206, 199, 203, 34, 27, 144, 196, 172, 176, 78, 226, 127, 139, 19, 64, 183, 235, 143, 233, 26, 219, 65, 235, 44, 77, 112]) }, PackedNode { ip_type: U4, saddr: V4(87.111.204.245:62561), pk: PublicKey([190, 44, 128, 10, 160, 251, 108, 73, 210, 253, 55, 77, 76, 31, 249, 7, 230, 65, 213, 3, 42, 53, 125, 141, 40, 34, 188, 26, 153, 254, 148, 127]) }, PackedNode { ip_type: U4, saddr: V4(70.228.66.19:33445), pk: PublicKey([191, 152, 20, 33, 131, 92, 146, 36, 203, 11, 47, 145, 240, 231, 80, 231, 17, 176, 83, 137, 196, 187, 86, 193, 127, 163, 95, 247, 66, 63, 213, 59]) }, PackedNode { ip_type: U4, saddr: V4(46.163.140.6:33445), pk: PublicKey([68, 191, 46, 13, 148, 55, 90, 44, 236, 217, 123, 149, 194, 0, 27, 93, 230, 147, 215, 0, 134, 234, 85, 239, 62, 167, 93, 77, 231, 51, 42, 61]) }, PackedNode { ip_type: U4, saddr: V4(91.121.66.124:33445), pk: PublicKey([78, 63, 125, 55, 41, 86, 100, 187, 208, 116, 27, 109, 188, 182, 67, 29, 108, 215, 127, 196, 16, 83, 56, 194, 252, 49, 86, 123, 245, 200, 34, 74]) }, PackedNode { ip_type: U4, saddr: V4(184.7.240.104:33445), pk: PublicKey([186, 108, 67, 234, 158, 59, 209, 27, 191, 108, 186, 80, 188, 231, 140, 74, 158, 224, 55, 136, 202, 170, 84, 198, 137, 176, 47, 40, 227, 56, 213, 14]) }, PackedNode { ip_type: U4, saddr: V4(46.193.0.139:11717), pk: PublicKey([190, 22, 2, 184, 81, 223, 133, 70, 207, 95, 141, 150, 201, 124, 16, 30, 162, 175, 236, 170, 162, 157, 72, 108, 173, 68, 72, 231, 240, 182, 75, 3]) }, PackedNode { ip_type: U4, saddr: V4(79.172.64.10:33445), pk: PublicKey([191, 221, 160, 60, 8, 16, 133, 203, 178, 68, 204, 179, 21, 102, 22, 41, 172, 35, 56, 76, 120, 124, 228, 230, 26, 92, 38, 174, 206, 225, 71, 104]) }]), eof: Eof }"
    );
}
