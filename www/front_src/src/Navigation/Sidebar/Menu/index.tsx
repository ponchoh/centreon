import React, { useState } from 'react';

import { equals, isNil } from 'ramda';
import { useNavigate } from 'react-router-dom';
import { useAtom } from 'jotai';

import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import makeStyles from '@mui/styles/makeStyles';

import { useMemoComponent } from '@centreon/ui';

import { Page } from '../../models';
import {
  navigationItemSelectedAtom,
  propsNavigationItemSelected,
} from '../sideBarAtoms';
import { closedDrawerWidth, openedDrawerWidth } from '../index';

import MenuItems from './MenuItems';
import icons from './icons';
import CollapsableItems from './CollapsableItems';

interface Props {
  isDrawerOpen: boolean;
  navigationData?: Array<Page>;
}

const useStyles = makeStyles((theme) => ({
  icon: {
    color: theme.palette.text.primary,
    fontSize: 26,
  },
}));

const NavigationMenu = ({
  isDrawerOpen,
  navigationData,
}: Props): JSX.Element => {
  const classes = useStyles();
  const navigate = useNavigate();

  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null);
  const [currentTop, setCurrentTop] = useState<number>();
  const [collapseScrollMaxHeight, setCollapseScrollMaxHeight] = useState<
    number | undefined
  >(undefined);
  const [maxWidthCollapsScroll, setMaxWidthCollapsScroll] = useState<
    number | undefined
  >(undefined);
  const [navigationItemSelected, setNavigationItemSelected] = useAtom(
    navigationItemSelectedAtom,
  );
  const levelName = 'level_0_Navigated';
  const currentWidth = isDrawerOpen ? openedDrawerWidth / 8 : closedDrawerWidth;

  const props = {
    collapseScrollMaxHeight,
    currentTop,
    currentWidth,
    hoveredIndex,
    isDrawerOpen,
    level: 1,
    maxWidthCollapsScroll,
    setCollapseScrollMaxHeight,
    setMaxWidthCollapsScroll,
  };

  const hoverItem = (
    e: React.MouseEvent<HTMLElement>,
    index: number | null,
    item: Page,
  ): void => {
    const rect = e.currentTarget.getBoundingClientRect();
    const { top } = rect;
    setCurrentTop(top);
    setHoveredIndex(index);
    setNavigationItemSelected({
      ...navigationItemSelected,
      level_0: { index, label: item.label, url: item?.url },
    });
  };

  const handleLeave = (): void => {
    setHoveredIndex(null);
  };

  const getUrlFromEntry = (entryProps: Page): string | null | undefined => {
    const page = !isNil(entryProps?.page) ? entryProps.page : '';
    const options = !isNil(entryProps?.options) ? entryProps.options : '';

    const urlOptions = `${page}${options}`;
    const url = entryProps.is_react
      ? entryProps.url
      : `/main.php?p=${urlOptions}`;

    return url;
  };

  const handlClickItem = (item: Page, level = 0): void => {
    if (!isNil(getUrlFromEntry(item))) {
      navigate(getUrlFromEntry(item) as string);
    }

    if (
      navigationItemSelected &&
      navigationItemSelected[`level_${level}_Navigated`]?.label !== item.label
    ) {
      Object.keys(navigationItemSelected).forEach((i: string) => {
        if (i.includes('_Navigated')) {
          delete navigationItemSelected[i];
        } else {
          navigationItemSelected[`${i}_Navigated`] = navigationItemSelected[i];
          delete navigationItemSelected[i];
        }
      });
    }

    setNavigationItemSelected(navigationItemSelected);
  };

  const isItemHovered = (
    object: Record<string, propsNavigationItemSelected> | null,
    level: string,
    index: number,
  ): boolean => {
    if (object && object[level]) {
      return object[level].index === index;
    }

    return false;
  };

  return (
    <List onMouseLeave={handleLeave}>
      {navigationData?.map((item, index) => {
        const MenuIcon = !isNil(item?.icon) && icons[item.icon];
        const hover =
          isItemHovered(navigationItemSelected, levelName, index) ||
          equals(hoveredIndex, index);

        return (
          <ListItem disablePadding key={item.label}>
            <MenuItems
              isRoot
              data={item}
              hover={hover}
              icon={<MenuIcon className={classes.icon} />}
              isDrawerOpen={isDrawerOpen}
              isOpen={index === hoveredIndex}
              onClick={(): void => handlClickItem(item)}
              onMouseEnter={(e: React.MouseEvent<HTMLElement>): void =>
                hoverItem(e, index, item)
              }
            />
            {Array.isArray(item?.children) &&
              item.children.length > 0 &&
              equals(index, hoveredIndex) && (
                <CollapsableItems
                  {...props}
                  data={item.children}
                  isCollapsed={index === hoveredIndex}
                  onClick={handlClickItem}
                />
              )}
          </ListItem>
        );
      })}
    </List>
  );
};

export default NavigationMenu;
