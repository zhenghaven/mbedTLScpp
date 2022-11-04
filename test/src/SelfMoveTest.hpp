// Copyright (c) 2022 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

#pragma once

#define MBEDTLSCPPTEST_SELF_MOVE_TEST(OBJ) \
	auto OBJ ## _PTR1 = &(OBJ); \
	auto OBJ ## _PTR2 = &(OBJ); \
	*(OBJ ## _PTR2) = std::move(*(OBJ ## _PTR1));
