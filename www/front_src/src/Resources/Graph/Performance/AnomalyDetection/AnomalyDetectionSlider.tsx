import { useState, useEffect } from 'react';

import { equals } from 'ramda';

import Typography from '@mui/material/Typography';
import AddIcon from '@mui/icons-material/Add';
import RemoveIcon from '@mui/icons-material/Remove';
import Slider from '@mui/material/Slider';
import makeStyles from '@mui/styles/makeStyles';
import FormControlLabel from '@mui/material/FormControlLabel';
import Checkbox from '@mui/material/Checkbox';
import Button from '@mui/material/Button';

import { IconButton } from '@centreon/ui';

const useStyles = makeStyles((theme) => ({
  body: {
    display: 'flex',
    flexDirection: 'column',
  },
  bodyContainer: {
    alignItems: 'center',
    display: 'flex',
    marginBottom: theme.spacing(2),
    marginTop: theme.spacing(5),
  },
  confirmButton: {
    marginLeft: theme.spacing(2),
  },
  container: {
    display: 'flex',
    flexDirection: 'column',
    justifyContent: 'space-evenly',
    padding: theme.spacing(2),
  },
  footer: {
    display: 'flex',
    justifyContent: 'flex-end',
  },
  header: {
    display: 'flex',
    flexDirection: 'column',
  },
  icon: {
    display: 'flex',
    flexDirection: 'column',
  },
  slider: {
    '& .MuiSlider-mark': {
      borderLeft: '1px solid',
      height: theme.spacing(2),
      width: 0,
    },
    '& .MuiSlider-thumb': {
      height: theme.spacing(3),
      width: 1,
    },
    '& .MuiSlider-valueLabel': {
      backgroundColor: theme.palette.primary.main,
      borderRadius: '50%',
    },
    '& .MuiSlider-valueLabel:before': {
      width: 0,
    },
    '& .MuiSlider-valueLabelOpen': {
      transform: 'translateY(-60%) scale(1)',
    },
    display: 'flex',
    justifyContent: 'space-evenly',
    width: theme.spacing(35),
  },
}));

const AnomalyDetectionSlider = (): JSX.Element => {
  const classes = useStyles();
  const dataSlider = {
    currentValue: 0.8,
    defaultValue: 2,
  };
  const step = 0.1;
  const [currentValue, setCurrentValue] = useState(dataSlider.currentValue);
  const [isDefaultValue, setIsDefaultValue] = useState(false);

  const marks = [
    {
      label: 'Default',
      value: dataSlider.defaultValue,
    },
  ];

  const handleChangeSlider = (event): void => {
    setCurrentValue(event.target.value);
    setIsDefaultValue(false);
  };

  const handleAdd = (): void => {
    const newCurrentValue = Number((step + currentValue).toFixed(1));
    setCurrentValue(newCurrentValue);
    setIsDefaultValue(false);
  };

  const handleRemove = (): void => {
    const newCurrentValue = Number((currentValue - step).toFixed(1));
    setCurrentValue(newCurrentValue);
    setIsDefaultValue(false);
  };

  const handleChangeCheckBox = (event): void => {
    setIsDefaultValue(event?.target.checked);
  };

  useEffect(() => {
    if (isDefaultValue) {
      setCurrentValue(dataSlider.defaultValue);
    }
    if (equals(currentValue, dataSlider.defaultValue)) {
      setIsDefaultValue(true);
    }
  }, [isDefaultValue, currentValue]);

  return (
    <div className={classes.container}>
      <div className={classes.header}>
        <Typography variant="h6">Manage envelop size</Typography>
        <Typography variant="caption">
          Changes to the envelop size will be applied immediately
        </Typography>
      </div>

      <div className={classes.body}>
        <div className={classes.bodyContainer}>
          <IconButton data-testid="add" size="small" onClick={handleRemove}>
            <div className={classes.icon}>
              <RemoveIcon fontSize="small" />
              <Typography variant="subtitle2">0</Typography>
            </div>
          </IconButton>

          <Slider
            aria-label="Small"
            className={classes.slider}
            marks={marks}
            max={5}
            min={0}
            size="small"
            step={step}
            value={currentValue}
            valueLabelDisplay="on"
            onChange={handleChangeSlider}
          />
          <IconButton data-testid="remove" size="small" onClick={handleAdd}>
            <div className={classes.icon}>
              <AddIcon fontSize="small" />
              <Typography variant="subtitle2">5</Typography>
            </div>
          </IconButton>
        </div>
        <FormControlLabel
          control={
            <Checkbox
              checked={isDefaultValue}
              onChange={handleChangeCheckBox}
            />
          }
          label="use default value"
        />
      </div>

      <div className={classes.footer}>
        <Button size="small" variant="text">
          Cancel
        </Button>
        <Button
          className={classes.confirmButton}
          size="small"
          variant="contained"
        >
          Confirm
        </Button>
      </div>
    </div>
  );
};

export default AnomalyDetectionSlider;
