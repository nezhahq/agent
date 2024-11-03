package temperature

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/shirou/gopsutil/v4/sensors"

	"github.com/nezhahq/agent/model"
	"github.com/nezhahq/agent/pkg/util"
)

var sensorIgnoreList = []string{
	"PMU tcal", // the calibration sensor on arm macs, value is fixed
	"noname",
}

func GetState(_ context.Context) ([]model.SensorTemperature, error) {
	temperatures, err := sensors.SensorsTemperatures()
	if err != nil {
		return nil, fmt.Errorf("SensorsTemperatures: %v", err)
	}

	var tempStat []model.SensorTemperature
	for _, t := range temperatures {
		if t.Temperature > 0 && !util.ContainsStr(sensorIgnoreList, t.SensorKey) {
			tempStat = append(tempStat, model.SensorTemperature{
				Name:        t.SensorKey,
				Temperature: t.Temperature,
			})
		}
	}

	slices.SortFunc(tempStat, func(a, b model.SensorTemperature) int {
		return strings.Compare(a.Name, b.Name)
	})

	return tempStat, nil
}
