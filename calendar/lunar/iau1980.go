/*
 * Copyright (C) 2014 ~ 2017 Deepin Technology Co., Ltd.
 *
 * Author:     jouyouyun <jouyouwen717@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package lunar

import (
	"math"
)

// T 是  儒略世纪数
// 返回 弧度
func GetEarthNutationParameter(T float64) (D, M, Mp, F, Omega float64) {
	T2 := T * T
	T3 := T2 * T

	/*平距角（如月对地心的角距离）*/
	D = ToRadians(297.85036 + 445267.111480*T - 0.0019142*T2 + T3/189474.0)

	/*太阳（地球）平近点角*/
	M = ToRadians(357.52772 + 35999.050340*T - 0.0001603*T2 - T3/300000.0)

	/*月亮平近点角*/
	Mp = ToRadians(134.96298 + 477198.867398*T + 0.0086972*T2 + T3/56250.0)

	/*月亮纬度参数*/
	F = ToRadians(93.27191 + 483202.017538*T - 0.0036825*T2 + T3/327270.0)

	/*黄道与月亮平轨道升交点黄经*/
	Omega = ToRadians(125.04452 - 1934.136261*T + 0.0020708*T2 + T3/450000.0)
	return
}

//天体章动系数类型变量
type NuationCoefficient struct {
	D       float64
	M       float64
	Mp      float64
	F       float64
	Omega   float64
	Sine1   float64
	Sine2   float64
	Cosine1 float64
	Cosine2 float64
}

var nuation = []NuationCoefficient{
	{0, 0, 0, 0, 1, -171996, -174.2, 92025, 8.9},
	{-2, 0, 0, 2, 2, -13187, -1.6, 5736, -3.1},
	{0, 0, 0, 2, 2, -2274, -0.2, 977, -0.5},
	{0, 0, 0, 0, 2, 2062, 0.2, -895, 0.5},
	{0, 1, 0, 0, 0, 1426, -3.4, 54, -0.1},
	{0, 0, 1, 0, 0, 712, 0.1, -7, 0},
	{-2, 1, 0, 2, 2, -517, 1.2, 224, -0.6},
	{0, 0, 0, 2, 1, -386, -0.4, 200, 0},
	{0, 0, 1, 2, 2, -301, 0, 129, -0.1},
	{-2, -1, 0, 2, 2, 217, -0.5, -95, 0.3},
	{-2, 0, 1, 0, 0, -158, 0, 0, 0},
	{-2, 0, 0, 2, 1, 129, 0.1, -70, 0},
	{0, 0, -1, 2, 2, 123, 0, -53, 0},
	{2, 0, 0, 0, 0, 63, 0, 0, 0},
	{0, 0, 1, 0, 1, 63, 0.1, -33, 0},
	{2, 0, -1, 2, 2, -59, 0, 26, 0},
	{0, 0, -1, 0, 1, -58, -0.1, 32, 0},
	{0, 0, 1, 2, 1, -51, 0, 27, 0},
	{-2, 0, 2, 0, 0, 48, 0, 0, 0},
	{0, 0, -2, 2, 1, 46, 0, -24, 0},
	{2, 0, 0, 2, 2, -38, 0, 16, 0},
	{0, 0, 2, 2, 2, -31, 0, 13, 0},
	{0, 0, 2, 0, 0, 29, 0, 0, 0},
	{-2, 0, 1, 2, 2, 29, 0, -12, 0},
	{0, 0, 0, 2, 0, 26, 0, 0, 0},
	{-2, 0, 0, 2, 0, -22, 0, 0, 0},
	{0, 0, -1, 2, 1, 21, 0, -10, 0},
	{0, 2, 0, 0, 0, 17, -0.1, 0, 0},
	{2, 0, -1, 0, 1, 16, 0, -8, 0},
	{-2, 2, 0, 2, 2, -16, 0.1, 7, 0},
	{0, 1, 0, 0, 1, -15, 0, 9, 0},
	{-2, 0, 1, 0, 1, -13, 0, 7, 0},
	{0, -1, 0, 0, 1, -12, 0, 6, 0},
	{0, 0, 2, -2, 0, 11, 0, 0, 0},
	{2, 0, -1, 2, 1, -10, 0, 5, 0},
	{2, 0, 1, 2, 2, -8, 0, 3, 0},
	{0, 1, 0, 2, 2, 7, 0, -3, 0},
	{-2, 1, 1, 0, 0, -7, 0, 0, 0},
	{0, -1, 0, 2, 2, -7, 0, 3, 0},
	{2, 0, 0, 2, 1, -7, 0, 3, 0},
	{2, 0, 1, 0, 0, 6, 0, 0, 0},
	{-2, 0, 2, 2, 2, 6, 0, -3, 0},
	{-2, 0, 1, 2, 1, 6, 0, -3, 0},
	{2, 0, -2, 0, 1, -6, 0, 3, 0},
	{2, 0, 0, 0, 1, -6, 0, 3, 0},
	{0, -1, 1, 0, 0, 5, 0, 0, 0},
	{-2, -1, 0, 2, 1, -5, 0, 3, 0},
	{-2, 0, 0, 0, 1, -5, 0, 3, 0},
	{0, 0, 2, 2, 1, -5, 0, 3, 0},
	{-2, 0, 2, 0, 1, 4, 0, 0, 0},
	{-2, 1, 0, 2, 1, 4, 0, 0, 0},
	{0, 0, 1, -2, 0, 4, 0, 0, 0},
	{-1, 0, 1, 0, 0, -4, 0, 0, 0},
	{-2, 1, 0, 0, 0, -4, 0, 0, 0},
	{1, 0, 0, 0, 0, -4, 0, 0, 0},
	{0, 0, 1, 2, 0, 3, 0, 0, 0},
	{0, 0, -2, 2, 2, -3, 0, 0, 0},
	{-1, -1, 1, 0, 0, -3, 0, 0, 0},
	{0, 1, 1, 0, 0, -3, 0, 0, 0},
	{0, -1, 1, 2, 2, -3, 0, 0, 0},
	{2, -1, -1, 2, 2, -3, 0, 0, 0},
	{0, 0, 3, 2, 2, -3, 0, 0, 0},
	{2, -1, 0, 2, 2, -3, 0, 0, 0},
}

var coefficient = SecondsToRadians(0.0001)

//计算某时刻的黄经章动干扰量
// T 儒略世纪数
// 返回弧度
func CalcEarthLongitudeNutation(T float64) float64 {
	D, M, Mp, F, Omega := GetEarthNutationParameter(T)
	var result float64
	for _, n := range nuation {
		theta := n.D*D + n.M*M + n.Mp*Mp + n.F*F +
			n.Omega*Omega
		result += (n.Sine1 + n.Sine2*T) * math.Sin(theta)
	}
	//乘以章动表的系数 0.0001 角秒
	return result * coefficient
}

/*计算某时刻的黄赤交角章动干扰量，dt是儒略千年数，返回值单位是度*/

// 计算某时刻的黄赤交角章动干扰量
// dt 是儒略世纪数
// 返回弧度
func CalcEarthObliquityNutation(dt float64) float64 {
	D, M, Mp, F, Omega := GetEarthNutationParameter(dt)
	var result float64
	len_nuation := len(nuation)
	for i := 0; i < len_nuation; i++ {
		// sita 弧度
		n := nuation[i]
		theta := n.D*D + n.M*M + n.Mp*Mp + n.F*F +
			n.Omega*Omega
		result += (n.Cosine1 + n.Cosine2*dt) * math.Cos(theta)
	}
	//乘以章动表的系数 0.0001 角秒
	return result * coefficient
}
